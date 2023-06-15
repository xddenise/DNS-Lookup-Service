package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.Random;
import java.util.Set;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {
        int index = 0;
        String hostname = node.getHostName();
        RecordType recordType = node.getType();
        String typeAsStr = recordType.name();

        // Write Header section
        int id = random.nextInt(65535);

        if (verboseTracing) {
            System.out.print("\n\n");
            System.out.println("Query ID     " + id + " " + hostname + "  " + typeAsStr + " --> " + server.getHostAddress());
        }

        // id
        message[index++] = (byte) ((id >> 8) & 0xFF);
        message[index++] = (byte) (id & 0xFF);

        // flags
        message[index++] = (byte) 0;
        message[index++] = (byte) 0;

        // qdcount
        message[index++] = (byte) 0;
        message[index++] = (byte) 1;

        //other counts
        message[index++] = (byte) 0;
        message[index++] = (byte) 0;
        message[index++] = (byte) 0;
        message[index++] = (byte) 0;
        message[index++] = (byte) 0;
        message[index++] = (byte) 0;

        // Write QNAME of Question section
        // convert hostname into qname
        String[] splitNames = hostname.split("\\.");
        for (String name: splitNames) {
            char[] chars = name.toCharArray();

            // write the length of this label
            message[index++] = (byte) chars.length;

            for (int i = 0; i<chars.length; i++) {
                message[index++] = (byte) chars[i];
            }
        }

        // QNAME ends with a zero byte
        index++;

        // Write QTYPE of Question section
        short typeCode = (short) recordType.getCode();
        message[index++] = (byte) (typeCode >> 8);
        message[index++] = (byte) typeCode;

        // Write QCLASS of Question section
        message[index++] = (byte) 0;
        message[index++] = (byte) 1;

        byte[] newMessage = Arrays.copyOf(message, index);
    
        // Send query packet
        DatagramPacket packet = new DatagramPacket(newMessage, newMessage.length, server, DEFAULT_DNS_PORT);
        socket.send(packet);

        byte[] response = new byte[512];
        DatagramPacket responsePacket = new DatagramPacket(response, 512, server, DEFAULT_DNS_PORT);

        try {
            socket.receive(responsePacket);
        } catch (SocketTimeoutException e) {
            if (verboseTracing) {
                System.out.print("\n\n");
                System.out.println("Query ID     " + id + " " + hostname + "  " + typeAsStr + " --> " + server.getHostAddress());
            }
            socket.send(packet);
            socket.receive(responsePacket);
        }
        ByteBuffer buffer = ByteBuffer.wrap(response);
        
        DNSServerResponse serverRes = new DNSServerResponse(buffer, id);

        return serverRes;
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        Set<ResourceRecord> rrs = new HashSet<>();

        // Header section
        int id = Short.toUnsignedInt(responseBuffer.getShort());
        short flags = responseBuffer.getShort();
        int a = (flags >> 10) & 0x1;
        boolean authoritative = a == 1;

        if (verboseTracing) {
            System.out.println("Response ID: " + id + " Authoritative = " + authoritative);
        }

        int qdCount = (int) responseBuffer.getShort();
        int anCount = (int) responseBuffer.getShort();
        int nsCount = (int) responseBuffer.getShort();
        int arCount = (int) responseBuffer.getShort();

        // Question section
        while (qdCount > 0) {
            byte curByte = responseBuffer.get();

            // Read QNAME, which ends with a 0 byte
            String query = "";
            while ((int) curByte != 0) {
                query += (char) curByte;
                curByte = responseBuffer.get();
            }

            // Read QTYPE and QCLASS
            responseBuffer.getInt();
            qdCount--;
        }


        // Answer, Authority, Additional section
        int numOfHeaderPrinted = 0;
        if (verboseTracing) {
            System.out.println("  Answers (" + anCount + ")");
            numOfHeaderPrinted++;
        }
        int numOfRR = anCount + nsCount + arCount;

        for (int i=0; i<numOfRR; i++) {
            if (verboseTracing) {
                if (i == anCount) {
                    System.out.println("  Nameservers (" + nsCount + ")");
                    numOfHeaderPrinted++;
                } else if (i == anCount + nsCount) {
                    System.out.println("  Additional Information (" + arCount + ")");
                    numOfHeaderPrinted++;
                }
            }

            // Read NAME
            String name = getNameFromBuffer(responseBuffer);

            // Read TYPE
            int typeCode = responseBuffer.getShort();
            RecordType type = RecordType.getByCode(typeCode);

            // Read CLASS
            responseBuffer.getShort();

            // Read TTL
            long ttl = responseBuffer.getInt();

            // Read RDLENGTH
            int rdLength = responseBuffer.getShort();

            // Read RDATA
            ResourceRecord rr = null;

            if (type == RecordType.SOA || type == RecordType.MX || type == RecordType.OTHER) {
                // skip reading rdata if type is SOA, MX, or OTHER
                responseBuffer.position(responseBuffer.position() + rdLength);
                rr = new ResourceRecord(name, type, ttl, "----");
            } else if (type == RecordType.A || type == RecordType.AAAA) {
                // Convert to InetAddress
                byte[] addr = new byte[rdLength];
                responseBuffer.get(addr, 0, rdLength);   

                try {
                    InetAddress result = InetAddress.getByAddress(addr);    
                    rr = new ResourceRecord(name, type, ttl, result);
                } catch (Exception e) {
                    // TODO
                    System.out.println(e);
                }    
            } else {
                String host = getNameFromBuffer(responseBuffer);
                rr = new ResourceRecord(name, type, ttl, host);
            }

            if (rr != null) {
                verbosePrintResourceRecord(rr, typeCode);
                cache.addResult(rr);
                if (type == RecordType.NS) {
                    rrs.add(rr);
                }
            }
        }

        if (verboseTracing && numOfHeaderPrinted < 3) {
            if (numOfHeaderPrinted == 1) {
                System.out.println("  Nameservers (" + nsCount + ")");
            }
            System.out.println("  Additional Information (" + arCount + ")");
        }

        return rrs;
    }

    private static String getNameFromBuffer(ByteBuffer responseBuffer) {
        String name = "";
        int labelCounter = 0;
        byte curByte = responseBuffer.get();
        int originalInd = -1;

        while ((int) curByte != 0) {
            if (labelCounter > 0) {
                // read label
                char c = (char) curByte;
                name += c;
                curByte = responseBuffer.get();
                if (--labelCounter == 0 && curByte != 0) name += ".";
                continue;
            }

            if ((int) ((curByte >> 6) & 0x3) == 3) {
                // a pointer, so set ind to offset
                int offset = curByte & 0x3F;
                curByte = responseBuffer.get();
                offset = (offset << 8) | (curByte & 0xFF);

                // remember the original position
                if (originalInd == -1) {
                    originalInd = responseBuffer.position();
                }

                // set new index to offset
                responseBuffer.position(offset);
            } else {
                // set the length of label
                labelCounter = curByte;
            }
            curByte = responseBuffer.get();
        }

        if (originalInd != -1) {
            responseBuffer.position(originalInd);
        }

        return name;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
}

