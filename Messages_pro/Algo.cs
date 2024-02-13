using Npgsql;
using System.Security.Cryptography;
using System.Text;


namespace Messages_pro
{
    public class Algo
    {
        #region Algo
        public static string chat1;
        public static string chat2;
        public static List<string?> chats = new List<string?>();
        static void Main(string[] args)
        {
            string connectionString = "Server=127.0.0.1;Port=5432;Database=postgres;User Id=postgres;Password=7257320";
            while (true)
            {

                while (true)
                {
                    Console.Clear();
                    Console.Write("1.Sign Up\n2.Log In\n\nEnter:");
                    string x = Console.ReadLine()!;
                    if (x == "1")
                    {
                        SignUp(connectionString);
                    }
                    else if (x == "2")
                    {
                        break;
                    }
                }
                bool check = LogIn(connectionString);
                #region If true
                if (check == true)
                {
                    while (true)
                    {
                        Console.Clear();
                        userList(connectionString);
                        Console.Write("Enter reciever: \nEnter back to [back]");
                        string choice = Console.ReadLine()!;
                        if (choice == "back")
                        {
                            break;
                        }
                        if (chats.Any(lets => lets == choice))
                        {
                            chat2 = choice;
                            Console.Clear();
                            GetMessages(connectionString);
                            createChat(connectionString);
                        }
                        else
                        {
                            Console.WriteLine("User not found!");
                            Thread.Sleep(4500);
                        }
                    }
                }
                #endregion
                else
                {
                    Console.WriteLine("Enter 1 or 2");
                    Thread.Sleep(4500);

                }
            }
        }
        #region SignUp
        static void SignUp(string s)
        {
            Console.Write("username:");
            string name = Console.ReadLine()!;
            Console.Write("password:");
            string pass = Console.ReadLine()!;
            using (NpgsqlConnection con = new NpgsqlConnection(s))
            {
                con.Open();
                string query = $"insert into users(username,password,salt) values(@val1, @val2, @val3);";
                NpgsqlCommand cmd = new NpgsqlCommand(query, con);
                cmd.Parameters.AddWithValue("val1", name);
                cmd.Parameters.AddWithValue("val2", toHash(pass, out byte[] salt));
                cmd.Parameters.AddWithValue("val3", Convert.ToHexString(salt));
                cmd.ExecuteNonQuery();
            }
        }
        #endregion
        #region toHash_override
        static string toHash(string str)
        {
            foreach (char c in str)
            {
                if (char.IsDigit(c))
                {
                    return str;
                }
            }
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(str));

                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("ATOM"));
                }
                return builder.ToString();
            }
        }
        #endregion

        #region Chat
        static void createChat(string s)
        {
            Console.Write("Enter message:");
            string message = Console.ReadLine()!;
            using (NpgsqlConnection con = new NpgsqlConnection(s))
            {
                con.Open();
                string query = $"insert into chats(chat1, chat2, messages) values(@val1,@val2,@val3);";
                NpgsqlCommand cmd = new NpgsqlCommand(query, con);
                cmd.Parameters.AddWithValue("val1", chat1);
                cmd.Parameters.AddWithValue("val2", chat2);
                cmd.Parameters.AddWithValue("val3", message);
                cmd.ExecuteNonQuery();
            }
        }
        #endregion
        #region GetMessages
        static void GetMessages(string s)
        {
            using (NpgsqlConnection con = new NpgsqlConnection(s))
            {
                con.Open();
                string query = $"select * from chats where (chat1 = @val1 and chat2 = @val2) or (chat1 = @val2 and chat2 = @val1);";
                NpgsqlCommand cmd = new NpgsqlCommand(query, con);
                cmd.Parameters.AddWithValue("val1", chat1);
                cmd.Parameters.AddWithValue("val2", chat2);
                NpgsqlDataReader? reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    if (reader["user1"].ToString() == chat2)
                    {
                        Console.WriteLine($"{chat2}'s message ### {reader["messanges"]}");
                    }
                    else
                    {
                        Console.WriteLine($" Your message ### {reader["messanges"]}");
                    }
                }
            }
        }
        #endregion
        #region Log In
        static bool LogIn(string s)
        {
            Console.Write("Username:");
            string name = Console.ReadLine()!;
            Console.Write("Password:");
            string pass = Console.ReadLine()!;
            using (NpgsqlConnection con = new NpgsqlConnection(s))
            {
                con.Open();
                string query = $"select * from users where username = @val1;";
                NpgsqlCommand cmd = new NpgsqlCommand(query, con);
                cmd.Parameters.AddWithValue("val1", name);
                var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    if (HashCheck(pass, reader["password"].ToString()!, reader["salt"].ToString()!))
                    {
                        chat1 = name;
                        return true;
                    }
                }
                return false;
            }
        }
        #endregion
        #region UserList
        static void userList(string s)
        {
            using (NpgsqlConnection con = new NpgsqlConnection(s))
            {
                con.Open();
                string query = $"select username from users where username <> @val;";
                NpgsqlCommand cmd = new NpgsqlCommand(query, con);
                cmd.Parameters.AddWithValue("val", chat1);
                var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    Console.WriteLine(reader["username"]);
                    chats.Add(reader["username"].ToString()!);
                }
            }
        }
        #endregion

        #region Hash
        static string toHash(string password, out byte[] salt)
        {

            const int key = 65;
            const int iter = 350000;
            HashAlgorithmName hashAlgo = HashAlgorithmName.SHA512;

            salt = RandomNumberGenerator.GetBytes(key);

            var hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iter,
                hashAlgo,
                key);

            return Convert.ToHexString(hash);
        }
        #endregion
        #region HashCheck
        static bool HashCheck(string password, string hash, string salt)
        {
            byte[] salts = Convert.FromHexString(salt);
            const int key = 65;
            const int iter = 350000;
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;
            var Compare = Rfc2898DeriveBytes.Pbkdf2(password, salts, iter, hashAlgorithm, key);
            return CryptographicOperations.FixedTimeEquals(Compare, Convert.FromHexString(hash));
        }
        #endregion
        #endregion
    }

}

