using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

public static class RelayWitch
{
    private const int listenPort = 6112;

    public static IPAddress GetBroadcast(IPAddress host, IPAddress mask)
    {
        byte[] broadcastIPBytes = new byte[4];
        byte[] hostBytes = host.GetAddressBytes();
        byte[] maskBytes = mask.GetAddressBytes();
        for (int i = 0; i < 4; i++)
        {
            broadcastIPBytes[i] = (byte)(hostBytes[i] | (byte)~maskBytes[i]);
        }
        return new IPAddress(broadcastIPBytes);
    }
    public static bool SameSubnet(this IPAddress address2, IPAddress address, IPAddress subnetMask)
    {
        IPAddress network1 = address.GetNetworkAddress(subnetMask);
        IPAddress network2 = address2.GetNetworkAddress(subnetMask);

        return network1.Equals(network2);
    }

    public static IPAddress GetNetworkAddress(this IPAddress address, IPAddress subnetMask)
    {
        byte[] ipAdressBytes = address.GetAddressBytes();
        byte[] subnetMaskBytes = subnetMask.GetAddressBytes();

        if (ipAdressBytes.Length != subnetMaskBytes.Length)
            throw new ArgumentException("Lengths of IP address and subnet mask do not match.");

        byte[] broadcastAddress = new byte[ipAdressBytes.Length];
        for (int i = 0; i < broadcastAddress.Length; i++)
        {
            broadcastAddress[i] = (byte)(ipAdressBytes[i] & (subnetMaskBytes[i]));
        }
        return new IPAddress(broadcastAddress);
    }

    private static void StartListener()
    {
        UdpClient listener = new UdpClient(listenPort);
        IPEndPoint source_address = new IPEndPoint(IPAddress.Any, listenPort);
        IPAddress[] localIPs = Dns.GetHostAddresses(Dns.GetHostName());
        Console.WriteLine("DesuRelay started...");
        Console.WriteLine("------------------------------");
        foreach (NetworkInterface netInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            Console.WriteLine("Name: " + netInterface.Name);
            Console.WriteLine("Description: " + netInterface.Description);
            Console.WriteLine("Addresses: ");
            IPInterfaceProperties ipProps = netInterface.GetIPProperties();
            foreach (UnicastIPAddressInformation addr in ipProps.UnicastAddresses)
            {
                Console.WriteLine(" " + addr.Address.ToString());
            }
            Console.WriteLine("*** ***");
        }
        Console.WriteLine("------------------------------");
        try
        {
            while (true)
            {
                Console.WriteLine("Waiting for broadcast");
                byte[] bytes = listener.Receive(ref source_address);
                bool proceed = true;
                foreach (IPAddress i in localIPs)
                {
                    if (i.Equals(source_address.Address))
                    {
                        proceed = false;
                    }
                }
                Console.WriteLine($"Received broadcast from {source_address}. Message {bytes.Length} bytes long.");
                Console.WriteLine("------------------------------");
                Console.WriteLine($" {Encoding.ASCII.GetString(bytes, 0, bytes.Length)}");
                Console.WriteLine("------------------------------");
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up && ni.SupportsMulticast && ni.GetIPProperties().GetIPv4Properties() != null)
                    {
                        int id = ni.GetIPProperties().GetIPv4Properties().Index;
                        if (NetworkInterface.LoopbackInterfaceIndex != id)
                        {
                            foreach (UnicastIPAddressInformation uip in ni.GetIPProperties().UnicastAddresses)
                            {
                                if (uip.Address.AddressFamily == AddressFamily.InterNetwork)
                                {
                                    IPEndPoint local = new IPEndPoint(address: uip.Address, port: 0);
                                    if (SameSubnet(local.Address, source_address.Address, uip.IPv4Mask) | proceed == false)
                                    {
                                        continue;
                                    }
                                    else
                                    {
                                        Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

                                        IPEndPoint target = new IPEndPoint(GetBroadcast(uip.Address, uip.IPv4Mask), listenPort);
                                        Console.WriteLine($"Local address {local}. Sender {source_address}. Destination {target}");
                                        s.SendTo(bytes, target);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch (SocketException e)
        {
            Console.WriteLine(e);
        }
        finally
        {
            listener.Close();
        }
    }

    public static void Main()
    {
        StartListener();
        Console.ReadKey();
    }
}
