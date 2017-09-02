package Captura;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.io.*;

import com.sun.xml.internal.ws.commons.xmlutil.Converter;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import javax.xml.crypto.Data;


public class Captura {

    /**
     * Main startup method
     *
     * @param args
     *          ignored
     */
    private static String asString(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0) {
                buf.append(':');
            }
            if (b >= 0 && b < 16) {
                buf.append('0');
            }
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }

        return buf.toString();
    }

    public static void main(String[] args) {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
        StringBuilder errbuf = new StringBuilder(); // For any error msgs

        /***************************************************************************
         * First get a list of devices on this system
         **************************************************************************/
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return;
        }

        System.out.println("Network devices found:");

        int i = 0;
        try{
            for (PcapIf device : alldevs) {
                String description =
                        (device.getDescription() != null) ? device.getDescription()
                                : "No description available";
                final byte[] mac = device.getHardwareAddress();
                String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);

            }//for

            BufferedReader br =new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Elige un dispositivo:");

            int disp=Integer.parseInt(br.readLine());

            PcapIf device = alldevs.get(disp); // We know we have atleast 1 device
            System.out.printf("\nChoosing '%s' on your behalf:\n",
                            (device.getDescription() != null) ? device.getDescription()
                                    : device.getName());

            /***************************************************************************
             * Second we open up the selected device
             **************************************************************************/
                /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
                64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam máx de trama */

            int snaplen = 64 * 1024;           // Capture all packets, no trucation
            int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
            int timeout = 10 * 1000;           // 10 seconds in millis
            Pcap pcap =
                    Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

            if (pcap == null) {
                System.err.printf("Error while opening device for capture: "
                        + errbuf.toString());
                return;
            }//if

            /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression ="ip"; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
            /****************/


            /***************************************************************************
             * Third we create a packet handler which will receive packets from the
             * libpcap loop.
             **********************************************************************/
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

                public void nextPacket(PcapPacket packet, String user) {

                    ArrayList<String> str = new ArrayList<String>();

                    System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                            new Date(packet.getCaptureHeader().timestampInMillis()),
                            packet.getCaptureHeader().caplen(),  // Length actually captured
                            packet.getCaptureHeader().wirelen(), // Original length
                            user                                 // User supplied object
                    );
                    /******Desencapsulado********/
                    for(int i=0;i<packet.size();i++){
                        System.out.printf("%02X ",packet.getUByte(i));
                        if(i%16==15)
                            System.out.println("");
                    }
                    System.out.println("\n\nEncabezado: "+ packet.toHexdump());



                    /*Trama a analizar*/
                    for(int i=0;i<packet.size();i++){
                      //  System.out.printf("%02X ",packet.getUByte(i));
                       // str.add(String.format("%02X", packet.getUByte(i)));
                           str.add(String.format("%02x", packet.getUByte(i)));
//                        if(i%16==15)
//                            System.out.println("");
                    }

                    System.out.println("");
                    System.out.println("Trama a analizar:");
                    int numero=(int)Long.parseLong(str.get(2), 16);
                    System.out.println(str);
                    String macOrigen= new String();
                    String macDestino= new String();
                    String rfc=new String();
                    String cabecera=new String();

                    int tamaño=0;
                    String ipO=new String();
                    String ipD=new String();
                    String byteVacio="00";
                    String protocolo= new String();
                    String longitudC=new String();
                    String pduTransporte= new String();
                    String pseudoEncabezado=new String();

                    int longitud=0;
                    int longitudTotal=0;



                    for (int y = 0; y < 6; y++) {
                            macOrigen = macOrigen + str.get(y);
                        }
                    for (int e = 6; e < 12; e++) {
                            macDestino = macDestino + str.get(e);
                        }
                    for (int z=12;z<14;z++){
                        rfc=rfc+str.get(z);
                    }
                    for (int z=14;z<15;z++){
                        cabecera=cabecera+str.get(z);
                        cabecera=cabecera.substring(1);
                        tamaño=(((int)Long.parseLong(cabecera, 16))*32)/8;
                    }
                    for(int z=26; z<30;z++){
                        ipO=ipO+str.get(z);
                    }
                    for(int z=30; z<34;z++){
                        ipD=ipD+str.get(z);
                    }

                    for(int z=16; z<18;z++){
                        longitud=longitud+(int)Long.parseLong(str.get(z), 16);

                        longitudC =String.format("%x00", (longitud-tamaño));

                    }

                    for(int z=(14+tamaño);z<=(longitud-tamaño);z++){
                        pduTransporte=pduTransporte+str.get(z);

                    }


                    String check=new String();
                    for(int z=14;z<(14+tamaño);z++){
                       check=check+str.get(z);

                    }

//                    int t_trama=longitud-tamaño;
//                    byte[] buf=new byte[t_trama+12];
//
//                    for (int i=0;i<4;i++){
//                       buf[i]= (byte) packet.getUByte(29+i);
//                       buf[i+4]= (byte) packet.getUByte(33+i);
//                    }
//                    buf[9]=0x00;
//                    buf[10]=(byte) packet.getUByte(24);


//                    for(int i=0;i<packet.size();i++){
//                        //  System.out.printf("%02X ",packet.getUByte(i));
//                        // str.add(String.format("%02X", packet.getUByte(i)));
//                       buf[i]= (byte) packet.getUByte(i);
////                        if(i%16==15)
////                            System.out.println("");
//                    }



                    protocolo=str.get(23);

                    pseudoEncabezado=ipO+ipD+byteVacio+protocolo+longitudC.substring(0,2)+longitudC.substring(2)+pduTransporte;

                                       longitudTotal=str.size();
                    System.out.println("");
                    System.out.println("Mac Origen:");
                    System.out.println(macOrigen);
                    System.out.println("Mac Destino:");
                    System.out.println(macDestino);
                    System.out.println("RFC");
                    System.out.println(rfc);
                    System.out.println("Protocolo");
                    System.out.println(protocolo);
                    System.out.println("Tamaño de encabezado");
                    System.out.println(tamaño);
                    System.out.println("IP Origen");
                    System.out.println(ipO);
                    System.out.println("IP Destino");
                    System.out.println(ipD);
                    System.out.println("Longitud");
                    System.out.println(longitud);
                    System.out.println("Longitud-tam");
                    System.out.println(longitud-tamaño);
                    System.out.println(14+tamaño);
                    System.out.println(longitudC);

                    System.out.println("LongitudTotal");
                    System.out.println(longitudTotal);

                    System.out.println("PDU Transporte");
                    System.out.println(pduTransporte);

                    /*Transformar pseudo encabezado*/
//                    String temporal= pseudoEncabezado.split(",");
//
//                    byte b[] = new byte[temporal.length];
//
//                    for (int i = 0; i < temporal.length; i++) {
//                        b[i] = (byte)(int)Long.parseLong(temporal[i], 16);
//                    }
//
//                    HexBinaryAdapter adapter = new HexBinaryAdapter();
//
//                    byte[] bytes=new byte[temporal.length];
//                    for (int i=0; i<temporal.length; i++) {
//                        //bytes[i] = Byte.parseByte(temporal[i],16);
//                        bytes =  new BigInteger(temporal[i], 16).toByteArray();
//                    }

                    HexBinaryAdapter adapter = new HexBinaryAdapter();
                    byte[] bytes = adapter.unmarshal(pseudoEncabezado);
                    byte[] checkS = adapter.unmarshal(check);

                    System.out.println("PseudoEncabezado");
                    System.out.println(pseudoEncabezado);
//                    System.out.println(Arrays.toString(temporal));

//                    System.out.println(Arrays.toString( new byte[]{(byte)(0xc0)}));

                    System.out.println(Arrays.toString(bytes));
                    System.out.println(Arrays.toString(checkS));
                    Checksum chek=new Checksum();

                    long resultado = chek.calculateChecksum(checkS);
                    System.out.printf("Valores del check: %02X\n",resultado);
                }
            };


            /***************************************************************************
             * Fourth we enter the loop and tell it to capture 10 packets. The loop
             * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
             * is needed by JScanner. The scanner scans the packet buffer and decodes
             * the headers. The mapping is done automatically, although a variation on
             * the loop method exists that allows the programmer to sepecify exactly
             * which protocol ID to use as the data link type for this pcap interface.
             **************************************************************************/
//            pcap.loop(10, jpacketHandler, "jNetPcap rocks!");

            pcap.loop(10, jpacketHandler, "jNetPcap rocks!");

            /***************************************************************************
             * Last thing to do is close the pcap handle
             **************************************************************************/
            pcap.close();
        }catch(IOException e){e.printStackTrace();}
    }
}
