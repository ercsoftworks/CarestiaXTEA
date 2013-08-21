using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CarestiaXTEA
{
   /***
 * 
 * Software Validation Program.
 * Created 2012 by Eric Carestia
 * Copyright EC Computers, LLC. T/A Eric Carestia.
 * 
 * 
 * <XTEA Algorithm description here>
 * <Notes on efficiency (space and amoritize time complexities)>
 * 
 * 
 * Original XTEA Algorithm created by Roger Needham and David Wheeler
 * 
 */


    public sealed class XTEA
    {
        /// <summary>
        /// Class XTEA data members
        /// </summary>
        private const int m_blockSize = 8;
        private const int m_keySize = 16;
        private const int m_delta = unchecked((int)0x9E3779B9);  //check "difference"
        private const int m_dSum = unchecked((int)0xC6EF3720); // sum on decrypt

        private byte[] m_keyBytes;
        private int[] m_key;
        private int m_rounds;

        /// <summary>
        /// Public Accessors
        /// </summary>
        public byte[] Key { get { return m_keyBytes; } }
        public int blockSize {get { return m_blockSize; } }
        public int keySize {get { return m_keySize; } }
        public int rounds {get { return m_rounds; } }


        /// <summary>
        /// Constructor for Class XTEA
        /// 
        /// This constructor takes two parameters:
        /// 
        /// The first is a byte array named "key", this array provides the keys for the
        /// XTEA encryption/decryption routine.
        /// 
        /// The second parameter is an 32-bit signed integer named "rounds" which indicates
        /// the desired number of rounds (how many times) to run the encryption and decryption routine.
        /// 
        /// The bytes in key[] are converted to 32-bit signed integers and placed into the private data
        /// member m_key[], which holds the decimal equivalent of the keys passed in.
        /// </summary>
        public XTEA(byte[] key, int rounds)
        {
            m_keyBytes = key;
            m_key = new int[4];
            m_key[0] = BitConverter.ToInt32(key, 0);
            m_key[1] = BitConverter.ToInt32(key, 4);
            m_key[2] = BitConverter.ToInt32(key, 8);
            m_key[3] = BitConverter.ToInt32(key, 12);
            m_rounds = rounds;
        }///End Constructor for Class XTEA

        ///EncryptBlock Method.
        public void EncryptBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff)
        {
            // Pack bytes into integers
            int v0 = BytesToInt(inBytes, inOff);
            int v1 = BytesToInt(inBytes, inOff + 4);

            int sum = 0;
            ///This is where the magic happens....
            ///and the XTEA algorithm is executed to perform
            ///the encryption on the inBytes (the bytes we want to encrypt)
            ///then place them into outBytes
            ///....and DON'T MIND THE MAN BEHIND THE CURTAIN!
            for (int i = 0; i != m_rounds; i++)
            {
                v0 += ((v1 << 4 ^ (int)((uint)v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
                sum += m_delta;
                v1 += ((v0 << 4 ^ (int)((uint)v0 >> 5)) + v0) ^ (sum + m_key[(int)((uint)sum >> 11) & 3]);
            }
            ///UNPACK YO SHIT SON!
            UnpackInt(v0, outBytes, outOff);
            UnpackInt(v1, outBytes, outOff + 4);

            return;
        }///End EncryptBlock Method.

        ///DecryptBlock Method 
        public void DecryptBlock(byte[] inBytes, int inOff, byte[] outBytes, int outOff)
        {
            // Pack bytes into integers
            int v0 = BytesToInt(inBytes, inOff);
            int v1 = BytesToInt(inBytes, inOff + 4);

            int sum = m_dSum;
            ///Decryption routine is exact mathematical inverse of encryption routine.
            for (int i = 0; i != m_rounds; i++)
            {
                v1 -= ((v0 << 4 ^ (int)((uint)v0 >> 5)) + v0) ^ (sum + m_key[(int)((uint)sum >> 11) & 3]);
                sum -= m_delta;
                v0 -= ((v1 << 4 ^ (int)((uint)v1 >> 5)) + v1) ^ (sum + m_key[sum & 3]);
            }

            UnpackInt(v0, outBytes, outOff);
            UnpackInt(v1, outBytes, outOff + 4);

            return;
        }///end DecryptBlock Method.

        ///Validate Method ---let's check our work.
        public bool Validate(byte[] plainText, byte[] decryptedText)
        {

            ///Now it's time to see if we're right.
            for (int k = 0; k < plainText.Length; k++)
            {
                ///byte by byte comparison of each element in plain and decrypted arrays
                if (plainText[k] != decryptedText[k])
                {
                    ///oops! we've got a mismatch and fucked up somewhere!
                   // Console.WriteLine("XTEA FAILED.");
                    return false;
                }

                ///Otherwise, keep checking until done.
            }

            //if the method reaches this line, the plain and decrypted arrays are
            //equivalent and has passed validation.
            return true;

        }///end of Validate method.


        ///BytesToInt Method ---Convert bytes to integers
        private int BytesToInt(byte[] b, int inOff)
        {
            //return BitConverter.ToInt32(b, inOff);
            return ((b[inOff++]) << 24) |
                    ((b[inOff++] & 255) << 16) |
                    ((b[inOff++] & 255) << 8) |
                    ((b[inOff] & 255));
        }///end BytesToInt Method.

        ///UnpackInt Method.
        private void UnpackInt(int v, byte[] b, int outOff)
        {
            ///shift bits back into proper places
            uint uv = (uint)v;
            b[outOff++] = (byte)(uv >> 24);
            b[outOff++] = (byte)(uv >> 16);
            b[outOff++] = (byte)(uv >> 8);
            b[outOff] = (byte)uv;
        }///end UnpackInt Method



       //Main method yo!  USE THIS FOR TESTING AND DIAGONOSTICS
        static void Main(string[] args)
        {
            Console.WriteLine("Brackets Validation Server Application");
            Console.WriteLine("Version 1.0");
            Console.WriteLine("Copyright EC Computers, LLC 2012");
            Console.WriteLine("Press Any key to continue.....");

            Console.ReadKey();

            ///Sample Block with random key values.
            byte[] xkey = new byte[16];
            Random rand = new Random();

            //We're going to perform the encryption/decryption of plaintext data 3 times, 
            //and for each iteration, a completely set of keys and plaintext will be generated
            //to ensure correctness of the XTEA algorithm.
            //Begin Test Routine Loop:
            for (int i = 0; i < 3; i++)
            {
                //seed the byte array b with random bytes.
                rand.NextBytes(xkey);

                //create new instance of XTEA class
                XTEA xtea = new XTEA(xkey, 32);

                /// String test = "Hello, this is a test of the XTEA Algorithm";
                System.Text.UTF8Encoding str = new System.Text.UTF8Encoding();
                Console.WriteLine("");

                //Now we create the plaintext we wish to encrypt.
                byte[] plain = new byte[32];
                //by filling it with random data, but could be any data (string, char, int, etc..)
                rand.NextBytes(plain);

                byte[] decrypted = new byte[plain.Length];
                byte[] encrypted = new byte[plain.Length];
                ///Verify plain,decrypted, and encrypted array lengths are equal.
                Console.WriteLine("Plaintext sizeof in bytes: " + plain.Length);
                Console.WriteLine("Encrypted sizeof in bytes: " + encrypted.Length);
                Console.WriteLine("Decrypted sizeof in bytes: " + decrypted.Length);
                Console.WriteLine("\nContent of Plaintext (decimal representation):");
                for (int j = 0; j < plain.Length; j++)
                {
                    if ((j != 0) && (j % 5 == 0))
                    {
                        Console.WriteLine();
                    }
                    Console.Write(plain[j] + "\t");

                }

                Console.WriteLine("\n\nPress Any Key to Encrypt/Decrypt Data...");


                Console.ReadKey();
                int iteration;
                ///Encrypt plaintext for 4 * m_rounds
                Console.Write("Encrypting Data....");
                for (iteration = 0; iteration < 4; iteration++)
                {
                    xtea.EncryptBlock(plain, (iteration * 8), encrypted, (iteration * 8));
                }
                Console.WriteLine("Complete");
                ///Decode the encrypted byte array for 4 * m_rounds...
                ///MUST BE EQUAL TO ENCRYPTION ROUTINE ITERATIONS!
                Console.Write("Decrypting Data....");
                for (iteration = 0; iteration < 4; iteration++)
                {
                    xtea.DecryptBlock(encrypted, (iteration * 8), decrypted, (iteration * 8));
                }
                Console.WriteLine("Complete");

                //Validate the encryption/decryption routines.
                Console.Write("Verifying....");
                xtea.Validate(plain, decrypted);

                ///Print out the plain and decrypted messages as Strings
                Console.WriteLine("Plaintext of plaintext message: " + str.GetString(plain, 0, 32));
                Console.WriteLine("Plaintext of decrypted message: " + str.GetString(decrypted, 0, 32));
                Console.Write("\nTest Routine " + (i + 1) + " of 3 Finished.");
                if (i == 2)
                {
                    Console.WriteLine(" Please Press Any Key to End Program...");
                }
                else
                {
                    Console.WriteLine(" Please Press Any Key to Continue...");
                }
                Console.ReadKey();


            }///end test routine loop.



        }//end Main()
    }///end Class XTEA
}
