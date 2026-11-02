using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

internal static class LocalProbe
{
    private static int Main(string[] args)
    {
        int port;
        if (args.Length != 2 || !Int32.TryParse(args[0], out port) || port < 1 || port > 65535 ||
            args[1].Length != 32 || !IsHex(args[1]))
            return 2;

        try
        {
            byte[] sent = Encoding.ASCII.GetBytes(args[1]);
            byte[] received = new byte[sent.Length];
            using (TcpClient client = new TcpClient(AddressFamily.InterNetwork))
            {
                client.Connect(IPAddress.Loopback, port);
                using (NetworkStream stream = client.GetStream())
                {
                    stream.ReadTimeout = 3000;
                    stream.WriteTimeout = 3000;
                    stream.Write(sent, 0, sent.Length);
                    int count = 0;
                    while (count < received.Length)
                    {
                        int n = stream.Read(received, count, received.Length - count);
                        if (n == 0) return 3;
                        count += n;
                    }
                }
            }
            if (Encoding.ASCII.GetString(received) != args[1]) return 4;
#if TARGET
            Console.WriteLine("target:ok");
#elif CONTROL
            Console.WriteLine("control:ok");
#else
            return 5;
#endif
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.GetType().Name);
            return 6;
        }
    }

    private static bool IsHex(string value)
    {
        foreach (char c in value)
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        return true;
    }
}
