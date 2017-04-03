using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.IO;

namespace DESCipherWPF
{
    class DESCipher
    {
        List<string> c;
        List<string> d;
        List<string> keys;
        List<string> keyEncoding;
        List<string> keyPermutations;
        string key,keyP, czero, dzero,message,ipMessage,lzero,rzero;
        static int[,] s = new int[,]{{
             14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
             0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
             4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
            15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},

            {
             15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
             3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
             0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
            13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},

            {
             10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
            13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
            13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
             1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},

            {
             7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
            13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
            10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
             3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},

            {
            2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
            14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
             4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
            11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},

            {
             12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
             10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
             9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
             4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
            {
             4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
             13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
             1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
             6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
             {
             13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
             1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
             7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
             2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11} };
        static int[] rzeroPermtutation =    {16,  7, 20, 21,
                                    29, 12, 28, 17,
                                     1, 15, 23, 26,
                                     5, 18, 31, 10,
                                     2,  8, 24, 14,
                                    32, 27,  3,  9,
                                    19, 13, 30,  6,
                                    22, 11,  4, 25};
        static int[] initial_key_permutaion = {57, 49,  41, 33,  25,  17,  9,
                                 1, 58,  50, 42,  34,  26, 18,
                                10,  2,  59, 51,  43,  35, 27,
                                19, 11,   3, 60,  52,  44, 36,
                                63, 55,  47, 39,  31,  23, 15,
                                 7, 62,  54, 46,  38,  30, 22,
                                14,  6,  61, 53,  45,  37, 29,
                                21, 13,   5, 28,  20,  12,  4};
        static int[] final_key_permutation =    {14, 17, 11, 24,  1,  5,
                                 3, 28, 15,  6, 21, 10,
                                23, 19, 12,  4, 26,  8,
                                16,  7, 27, 20, 13,  2,
                                41, 52, 31, 37, 47, 55,
                                30, 40, 51, 45, 33, 48,
                                44, 49, 39, 56, 34, 53,
                                46, 42, 50, 36, 29, 32};
        static int[] initial_message_permutation =    {58, 50, 42, 34, 26, 18, 10, 2,
                                        60, 52, 44, 36, 28, 20, 12, 4,
                                        62, 54, 46, 38, 30, 22, 14, 6,
                                        64, 56, 48, 40, 32, 24, 16, 8,
                                        57, 49, 41, 33, 25, 17,  9, 1,
                                        59, 51, 43, 35, 27, 19, 11, 3,
                                        61, 53, 45, 37, 29, 21, 13, 5,
                                        63, 55, 47, 39, 31, 23, 15, 7};
        static int[] message_expansion =  {32,  1,  2,  3,  4,  5,
                             4,  5,  6,  7,  8,  9,
                             8,  9, 10, 11, 12, 13,
                            12, 13, 14, 15, 16, 17,
                            16, 17, 18, 19, 20, 21,
                            20, 21, 22, 23, 24, 25,
                            24, 25, 26, 27, 28, 29,
                            28, 29, 30, 31, 32,  1};
        static int[] final_message_permutation =  {40,  8, 48, 16, 56, 24, 64, 32,
                                    39,  7, 47, 15, 55, 23, 63, 31,
                                    38,  6, 46, 14, 54, 22, 62, 30,
                                    37,  5, 45, 13, 53, 21, 61, 29,
                                    36,  4, 44, 12, 52, 20, 60, 28,
                                    35,  3, 43, 11, 51, 19, 59, 27,
                                    34,  2, 42, 10, 50, 18, 58, 26,
                                    33,  1, 41,  9, 49, 17, 57, 25};
        
        public DESCipher(string input,string keyTb)
        {
            key = HexToBinary(keyTb);
            keyP = KeyPlus(key, initial_key_permutaion); // K+ Permutation - First Step
            czero = KeyPlusSplitting(keyP, false); //Split Key in C0
            dzero = KeyPlusSplitting(keyP, true); //Split Key in D0
            keys = new List<string>();
            c = new List<string>();
            d = new List<string>();

            keyPermutations = SixteenShifts(czero, dzero, final_key_permutation);//16 keys - Final Permutation
            keyEncoding = new List<string>();
            for (int i = 15; i >= 0; i--)
            {
                keyEncoding.Add(keyPermutations[i]);
            }
            message = HexToBinary(input); // Message to Binary
            ipMessage = MessageToIp(message, initial_message_permutation); // Initial Permutation Message
            lzero = KeyPlusSplitting(ipMessage, false); // Split Message in L0
            rzero = KeyPlusSplitting(ipMessage, true); // Split Message in R0
            
           
        }
        public string Encrypt()
        {
            WriteToFile();
            return Iterations(lzero, rzero, keyPermutations);
        }
        public string Decrypt()
        {
            WriteToFile();
           return Iterations(KeyPlusSplitting(MessageToIp(message, initial_message_permutation), false), KeyPlusSplitting(MessageToIp(message, initial_message_permutation), true), keyEncoding);
        }
        void WriteToFile()
        {
            //string path = "log.txt";
            //string text = "";
            //text += "K binary: " + key;
            //string kupa = "K+ binary: " + keyP;
            //List<string> lines = new List<string>();
            //int j = 2;
            //for(int i=0;i<c.Capacity;i++)
            //{
            //    lines.Add("");
            //    lines[i]="C" + i + ": "+ c[i];
            //    lines[i] += "   D" + i + ":   "+ d[i];
            //}
            //for (int i = 0; i < keyPermutations.Capacity; i++)
            //{
            //    lines.Add("");
            //    lines[i] = "K" + (i + 1) + ": " + keyPermutations[i];
            //}

            //// WriteAllLines creates a file, writes a collection of strings to the file,
            //// and then closes the file.  You do NOT need to call Flush() or Close().
            //System.IO.File.WriteAllLines(path, lines);



        }
        public string HexToBinary(string hex)
        {
            string binary = "";
            binary = String.Join(String.Empty,
            hex.Select(
            c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')
            )
            );
            return binary;
        }
        public string KeyPlus(string key, int[] numArray)
        {
            string keyPluss = "";
            char[] tmp = new char[56];
            int count = 0;
            for (int i = 0; i < numArray.Length; i++)
            {
                tmp[i] = key[numArray[count++] - 1];
            }
            keyPluss = new string(tmp);
            return keyPluss;
        }
        public string KeyPlusSplitting(string keyPlus, bool firstTime)
        {
            string czero = "";
            string dzero = "";
            string last = "";
            if (firstTime == false)
            {
                for (int i = 0; i < keyPlus.Length / 2; i++)
                {
                    czero += keyPlus[i];
                }
                last = czero;
            }
            else
            {
                for (int i = keyPlus.Length / 2; i < keyPlus.Length; i++)
                {
                    dzero += keyPlus[i];
                }
                last = dzero;
            }
            return last;
        }
        public string ShiftC(string cn)
        {
            string cn1 = "";
            char tmp = cn[0];
            for (int i = 0; i <= cn.Length - 1; i++)
            {
                if (i == cn.Length - 1)
                {
                    cn1 += tmp;
                }
                else
                    cn1 += cn[i + 1];

            }
            return cn1;
        }
        public string ShiftD(string dn)
        {
            string dn1 = "";
            char tmp = dn[0];
            for (int i = 0; i <= dn.Length - 1; i++)
            {
                if (i == dn.Length - 1)
                {
                    dn1 += tmp;
                }
                else
                    dn1 += dn[i + 1];

            }
            return dn1;
        }
        public List<string> SixteenShifts(string czero, string dzero, int[] pc2)
        {
            List<string> keyPermutation = new List<string>();
            int[] numberShifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            int counter = 0;
            for (int i = 0; i < 16; i++)
            {
                while (counter < numberShifts[i])
                {
                    czero = ShiftC(czero);
                    dzero = ShiftD(dzero);
                    counter++;
                }
                counter = 0;
                c.Add(czero);
                d.Add(dzero);
            }
            for (int i = 0; i < c.Count; i++)
            {
                keys.Add(c.ElementAt(i) + d.ElementAt(i));
            }
            int count = 0;
            for (int i = 0; i < keys.Count; i++)
            {
                char[] tmp = new char[48];
                for (int j = 0; j < pc2.Length; j++)
                {

                    tmp[j] = keys[i][pc2[j] - 1];
                }
                keyPermutation.Add(new string(tmp));
            }
            return keyPermutation;

        }
        static string MessageToIp(string message, int[] ipArray)
        {
            string ip = "";
            char[] tmp = new char[message.Length];
            for (int i = 0; i < message.Length; i++)
            {
                tmp[i] = message[ipArray[i] - 1];
            }
            ip = new string(tmp);
            return ip;
        }
        static string EPermutation(string r, int[] EArray)
        {
            string ePermuted = "";
            char[] tmp = new char[48];
            for (int i = 0; i < 48; i++)
            {
                tmp[i] = r[EArray[i] - 1];
            }
            ePermuted = new string(tmp);
            return ePermuted;
        }
        static string XOR(string r, string k)
        {
            string xored = "";
            char[] tmp = new char[r.Length];
            for (int i = 0; i < r.Length; i++)
            {
                xored += (Convert.ToInt32(r[i]) ^ Convert.ToInt32(k[i])).ToString();
            }
            return xored;
        }
        static int ConvertToColumn(string binary, int position)
        {
            int dec = 0;
            string mod = "";
            mod += binary[1 + (6 * position)] + "" + binary[2 + (6 * position)] + "" + binary[3 + (6 * position)] + "" + binary[4 + (6 * position)];
            int[] z = { 3, 2, 1, 0 };
            for (int i = 0; i < 4; i++)
            {
                if (mod[i] == '1')
                {
                    dec += Convert.ToInt32(Math.Pow(2, z[i]));
                }
            }
            return dec;
        }
        static int ConvertToRow(string binary, int position)
        {
            int dec = 0;
            string mod = "";
            mod += binary[0 + (6 * position)] + "" + binary[5 + (6 * position)] + "";
            int[] z = { 1, 0 };
            for (int i = 0; i < 2; i++)
            {
                if (mod[i] == '1')
                {
                    dec += Convert.ToInt32(Math.Pow(2, z[i]));
                }
            }
            return dec;
            return dec;
        }
        static string SBoxes(string er)
        {
            int currentColumn, currentRow;
            string sboxed = "";
            for (int i = 0; i < 8; i++)
            {
                currentColumn = ConvertToColumn(er, i);
                currentRow = ConvertToRow(er, i);
                sboxed += Convert.ToString(s[i, (currentRow * 16) + currentColumn], 2).PadLeft(4, '0');


            }
            return sboxed;

        }
        static string RPermutation(int[] rpArray, string sboxed)
        {
            string rPermuted = "";
            char[] tmp = new char[32];
            for (int i = 0; i < 32; i++)
            {
                tmp[i] = sboxed[rpArray[i] - 1];
            }
            rPermuted = new string(tmp);

            return rPermuted;
        }
        static string Iterations(string lzero, string rzero, List<string> keys)
        {
            string ff = "";
            string reverse = "";
            List<string> r = new List<string>();
            r.Add(rzero);
            List<string> l = new List<string>();
            l.Add(lzero);
            for (int i = 0; i < 16; i++)
            {
                ff = FuncionF(r[i], keys[i]);
                r.Add(XOR(l[i], ff));
                l.Add(r[i]);
            }
            reverse = r[16] + "" + l[16];
            string finalMessageBinary = FinalMessagePermutation(reverse);
            return BinaryToHex(finalMessageBinary);
        }
        static string FuncionF(string r, string key)
        {
            r = EPermutation(r, message_expansion);
            r = XOR(r, key);
            r = SBoxes(r);
            r = RPermutation(rzeroPermtutation, r);
            return r;
        }
        static string FinalMessagePermutation(string reverse)
        {
            string finalPermutation = "";
            //char[] tmp = new char[reverse.Length];
            for (int i = 0; i < reverse.Length; i++)
            {
                finalPermutation += reverse[final_message_permutation[i] - 1];
            }
            return finalPermutation;
        }
        static string BinaryToHex(string binary)
        {
            StringBuilder result = new StringBuilder(binary.Length / 8 + 1);

            // TODO: check all 1's or 0's... Will throw otherwise

            int mod4Len = binary.Length % 8;
            if (mod4Len != 0)
            {
                // pad to length multiple of 8
                binary = binary.PadLeft(((binary.Length / 8) + 1) * 8, '0');
            }

            for (int i = 0; i < binary.Length; i += 8)
            {
                string eightBits = binary.Substring(i, 8);
                result.AppendFormat("{0:X2}", Convert.ToByte(eightBits, 2));
            }

            return result.ToString();

        }
    }
}