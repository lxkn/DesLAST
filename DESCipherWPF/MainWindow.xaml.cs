using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;

namespace DESCipherWPF
{
    /// <summary>
    /// Logika interakcji dla klasy MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private bool FromFile = false;
        string FileName = "data.bin";
        DESCipher des;
        public MainWindow()
        {
            InitializeComponent();
        }

        private void buttonEncrypt_Click(object sender, RoutedEventArgs e)
        {
            if (FromFile)
            {
                
                ReadBytesFromFile(true, tbFileName.Text);
            }
            else
            {
                des = new DESCipher(tbInput.Text, tbKey.Text);
                tbOutput.Text = des.Encrypt();
            }

        }

        private void buttonDecrypt_Click(object sender, RoutedEventArgs e)
        {
            if (FromFile)
            {
                ReadBytesFromFile(false, tbFileName.Text);
            }
            else
            {
                des = new DESCipher(tbInput.Text, tbKey.Text);
                tbOutput.Text = des.Decrypt();
            }
        }

        public void ReadBytesFromFile(bool Encrypt, string path)
        {
            List<string> Output = new List<string>();
            byte[] fileBytes = File.ReadAllBytes(path);

            using (BinaryReader b = new BinaryReader(File.Open(path, FileMode.Open)))
            {
                // 2.
                // Position and length variables.
                int pos = 0;
                // 2A.
                // Use BaseStream.
                int length = (int)b.BaseStream.Length;
                while (pos < length)
                {
                    // 3.
                    // Read integer.
                    var v = b.ReadInt64();
                    string hex = v.ToString("X").PadLeft(16,'0');
                    pos += sizeof(System.Int64);

                    var temp = new DESCipher(hex, tbKey.Text);
                    if (Encrypt)
                        Output.Add(temp.Encrypt());
                    else
                        Output.Add(temp.Decrypt());

                    // 4.
                    // Advance our position variable.
                }
            }
            WriteBytesToFile(Output);
        }

        public void WriteBytesToFile(List<string> output)
        {
            using (BinaryWriter w = new BinaryWriter(File.Open("input.bin", FileMode.Open)))
            {
                foreach (string o in output)
                {
                    //long temp = Int64.Parse(o)
                    long temp = Convert.ToInt64(o, 16);
                    w.Write(temp);
                }
            }

        }

        private void cbFromFile_Checked(object sender, RoutedEventArgs e)
        {
            if ((bool)cbFromFile.IsChecked)
            {
                tbInput.IsEnabled = false;
                tbOutput.IsEnabled = false;
                FromFile = true;
            }
            else
            {
                tbInput.IsEnabled = true;
                tbOutput.IsEnabled = true;
                FromFile = false;
            }
        }
    }
}
