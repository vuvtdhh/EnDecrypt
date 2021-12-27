using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace EnDecrypt
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(string propertyName = "")
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public MainWindow()
        {
            InitializeComponent();
        }
        #region command
        private void CommandBinding_CanExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }
        private void Minimize_Executed(object sender, ExecutedRoutedEventArgs e)
        {
            SystemCommands.MinimizeWindow(this);
        }
        private void Close_Executed(object sender, ExecutedRoutedEventArgs e)
        {
            SystemCommands.CloseWindow(this);
        }
        #endregion

        private string _password;
        public string Password
        {
            get { return _password; }
            set
            {
                _password = value;
                NotifyPropertyChanged(nameof(Key));
            }
        }
        private string _salt;
        public string Salt
        {
            get { return _salt; }
            set
            {
                _salt = value;
                NotifyPropertyChanged(nameof(Key));
            }
        }

        private string _plain;
        public string Plain
        {
            get { return _plain; }
            set
            {
                _plain = value;
                NotifyPropertyChanged(nameof(Plain));
            }
        }

        private string _encrypted;
        public string Encrypted
        {
            get { return _encrypted; }
            set
            {
                _encrypted = value;
                NotifyPropertyChanged(nameof(Encrypted));
            }
        }

        //private const int SALT_SIZE = 24; // size in bytes
        private const int HASH_SIZE = 24; // size in bytes
        private const int ITERATIONS = 1000; // number of pbkdf2 iterations

        private async void Excecute(string input, byte[] passwordBytes, byte[] saltBytes)
        {
            try
            {
                Func<string> encrypt = () =>
                {
                    using (Aes myAes = Aes.Create())
                    {
                        int iterations = 1000;
                        Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, iterations);
                        myAes.Key = key.GetBytes(myAes.KeySize / 8);
                        myAes.IV = key.GetBytes(myAes.BlockSize / 8);
                        myAes.Padding = PaddingMode.PKCS7;
                        myAes.Mode = CipherMode.CBC;


                        // Encrypt the string to an array of bytes.
                        byte[] encrypted = EncryptStringToBytes_Aes(input, myAes.Key, myAes.IV, myAes.Padding, myAes.Mode);

                        return Convert.ToBase64String(encrypted);
                    }
                };

                Task<string> encryptTask = new Task<string>(encrypt);
                encryptTask.Start();
                await encryptTask;
                Encrypted = encryptTask.Result;
            }
            catch (Exception e)
            {
                MessageBox.Show(string.Format("Error: {0}", e.Message), "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV, PaddingMode paddingMode, CipherMode cipherMode)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Padding = paddingMode;
                aesAlg.Mode = cipherMode;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV, PaddingMode paddingMode, CipherMode cipherMode)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Padding = paddingMode;
                aesAlg.Mode = cipherMode;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        private string _mac;
        private string _serial;
        public string Mac
        {
            get { return _mac; }
            set
            {
                _mac = value;
                NotifyPropertyChanged(nameof(Mac));
            }
        }
        public string Serial
        {
            get { return _serial; }
            set
            {
                _serial = value;
                NotifyPropertyChanged(nameof(Serial));
            }
        }
        private async void GetHardwareInfoButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Func<string> getMac = () =>
                {
                    NetworkInterface[] n;
                    string macAddresses = string.Empty;
                    foreach (NetworkInterface nic in n = NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (nic.OperationalStatus == OperationalStatus.Up)
                        {
                            macAddresses += nic.GetPhysicalAddress().ToString();
                            break;
                        }
                    }
                    return macAddresses;
                };

                Task<string> getMacTask = new Task<string>(getMac);


                Func<string> getSerial = () =>
                {
                    //Win32_BIOS
                    ManagementObjectSearcher ComSerial = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard");
                    string serial = string.Empty;
                    foreach (ManagementObject wmi in ComSerial.Get())
                    {
                        try
                        {
                            serial = wmi.GetPropertyValue("SerialNumber").ToString();
                        }
                        catch { }
                    }
                    return serial;
                };

                Task<string> getSerialTask = new Task<string>(getSerial);

                getMacTask.Start();
                getSerialTask.Start();

                await getMacTask;
                await getSerialTask;


                Mac = getMacTask.Result;
                Serial = getSerialTask.Result;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private Aes PreparingAes()
        {
            byte[] passwordBytes = Encoding.ASCII.GetBytes(Password ?? string.Empty);
            byte[] saltBytes = Encoding.ASCII.GetBytes(Salt ?? string.Empty);

            Aes aes = null;
            if (passwordBytes.Length > 0 && saltBytes.Length >= 8)
            {
                aes = Aes.Create();
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, ITERATIONS);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;
            }
            return aes;
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            using (Aes aes = PreparingAes())
            {
                byte[] encrypted = EncryptStringToBytes_Aes(Plain, aes.Key, aes.IV, aes.Padding, aes.Mode);
                Encrypted = Convert.ToBase64String(encrypted);
            }
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            using (Aes aes = PreparingAes())
            {
                byte[] encryptedBytes = Convert.FromBase64String(Encrypted);
                Plain = DecryptStringFromBytes_Aes(encryptedBytes, aes.Key, aes.IV, aes.Padding, aes.Mode);
            }
        }
    }
}
