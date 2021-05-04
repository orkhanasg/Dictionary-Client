package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.util.*;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.Set;
import java.io.Console;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();
    private static int pointer = 0; //  pointer for decoding the query
    private static int[] generatedQueryIDs = new int[65536];
    private static int totalQueryCount = 0;
    private static DNSCache cache = DNSCache.getInstance();
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
  * Helper function that finds int value of 2 bytes (short to int)
  *
  * @param b1 left byte
  * @param b2 right byte
  * @return 256 * b1 + b2 as integer
  **/
  public static int getIntFromTwoBytes(byte b1, byte b2) {
    return ((b1 & 0xFF) << 8) + (b2 & 0xFF);
  }

/**
  * Helper function that finds int value of 4 bytes (4 bytes to int)
  *
  * @param b1 first byte
  * @param b2 second byte
  * @param b3 third byte
  * @param b4 fourth byte
  * @return 16777216 * b1 + 65536 * b2 + 256 * b3 + b4 as integer
  **/
  private static int getIntFromFourBytes(byte b1, byte b2, byte b3, byte b4) {
    return ((b1 & 0xFF) << 24) + ((b2 & 0xFF) << 16) + ((b3 & 0xFF) << 8) + (b4 & 0xFF);
  }

 /**
  * Recursively resolve the compressed name starting from ptr
  *
  * @param buffer byte array to be resolved
  * @param ptr initial location to start resolving
  * @return resolved compressed name
  **/
  private static String getNameFromPointer(byte[] buffer, int ptr){
    String name = "";
    while(true) {
      int labelLength = buffer[ptr++] & 0xFF;
      if (labelLength == 0)
        break;
      // Identify message compression used, recursive call to retrieve name
      else if (labelLength >= 192) {
        int newPtr = (buffer[ptr++] & 0xFF) + 256 * (labelLength - 192);
        name += getNameFromPointer(buffer, newPtr);
        break;
      }
      // standard function to decode encoded name
      else {
        for (int i = 0; i < labelLength; i++) {
          char ch = (char) (buffer[ptr++] & 0xFF);
          name += ch;
        }
        name += '.';
      }
    }

    pointer = ptr;
    if (name.length() > 0 && name.charAt(name.length() - 1) == '.') {
      name = name.substring(0, name.length() - 1);
    }
    return name;
  }

  /**
  * Generates a random ID between 0 and 655536, if it's generated before,
  * tries until generating a unique one
  *
  * @return a new and unique query ID
  **/
  public static int getNewUniqueQueryID() {
    int next = random.nextInt(65536);
    for (int i = 0; i < totalQueryCount; i++){
      if (generatedQueryIDs[i] == next) {
        return getNewUniqueQueryID();
      }
    }
    generatedQueryIDs[totalQueryCount++] = next;
    return next;
  }

  /**
     * Generate a transactionID.
     *
     * @return A transactionID.
     */
    private static int getTransactionID() {
        return (int) (random.nextInt() & 0xFFFF);
    }

    /**
     * Add given set of resource record into cache
     *
     * @return.
     */
    private static void addAllToCache(Set<ResourceRecord> input) {
        for (ResourceRecord r : input) {
            cache.addResult(r);
        }
    }


    /**
     * Builds the query, encodes it, and sends it to the server, and returns the response.
     * Method to encode query as a message in the domain protocol
  
  * @param message Byte array used to store the query to DNS servers.
  * @param queryID uniquely generated ID
  * @param node Host name and record type to be used for the query.
  * @param server  The IP address of the server to which the query is being sent.
  * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
  * 
  */
  public static DNSServerResponse buildAndSendQuery(byte[] message, int queryID, DNSNode node, InetAddress server)  {
    int thirdByte = queryID >>> 8;
    int forthByte = queryID & 0xff;
    message[0] = (byte) thirdByte;
    message[1] = (byte) forthByte;
    int QROpcodeAATCRD = 0; // 0 iterative, 1 recursive
    message[2] = (byte) QROpcodeAATCRD;
    int RAZRCODE = 0;
    message[3] = (byte) RAZRCODE;
    int QDCOUNT = 1;
    message[4] = (byte) 0;
    message[5] = (byte) QDCOUNT;
    int ANCOUNT = 0;
    message[6] = (byte) 0;
    message[7] = (byte) ANCOUNT;
    int NSCOUNT = 0;
    message[8] = (byte) 0;
    message[9] = (byte) NSCOUNT;
    int ARCOUNT = 0;
    message[10] = (byte) 0;
    message[11] = (byte) ARCOUNT;
    int ptr = 12;
    String[] labels = node.getHostName().split("\\.");
    for (int i = 0 ; i < labels.length; i++) {
      String label = labels[i];
      message[ptr++] = (byte) label.length();
      for (char c : label.toCharArray()) {
        message[ptr++] = (byte) ((int) c);
      }
    }
    message[ptr++] = (byte) 0; //end of QNAME
    int QTYPE = node.getType().getCode();
    message[ptr++] = (byte) ((QTYPE >>> 8) & 0xff);
    message[ptr++] = (byte) (QTYPE & 0xff);
    int QCLASS = 1; // always Internet(IN)
    message[ptr++] = (byte) 0;
    message[ptr++] = (byte) QCLASS;
    
      ByteBuffer response = ByteBuffer.wrap(Arrays.copyOfRange(message, 0, ptr));
      int transactionID =  getTransactionID();
      DNSServerResponse serverResponse = new DNSServerResponse(response, transactionID);


            return  serverResponse;
  }

                
 

      /**
  * Decode single Resorce Record in one of the following fields: answers, nameservers or
  * additional information, put it to cache if it's answer 
  *
  * @param responseBuffer a byte array as response buffer of a DNSServerResponse object, received response from DNS server
  *                     
  * @return decoded single resource record
  **/
  private static ResourceRecord decodeSingleRecord(byte[] responseBuffer){
    ResourceRecord record = null;
    String hostName = getNameFromPointer(responseBuffer, pointer);
    int typeCode = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
    int classCode = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
    long TTL = getIntFromFourBytes(responseBuffer[pointer++], responseBuffer[pointer++], responseBuffer[pointer++], responseBuffer[pointer++]);
    int RDATALength = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
    boolean errorOccured = false;
    if (typeCode == 1) { // A IPv4
      String address = "";
      for (int j = 0; j < RDATALength; j++) {
        int octet = responseBuffer[pointer++] & 0xFF;
        address += octet + ".";
      }
      address = address.substring(0, address.length() - 1);
      InetAddress addr = null;
      try {
        addr = InetAddress.getByName(address);
        record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, addr);
        verbosePrintResourceRecord(record, 0);
      } catch (UnknownHostException e){
        errorOccured = true;
      }
    }
    else if (typeCode == 28) { // AAAA IPv6
      String address = "";
      for (int j = 0; j < RDATALength / 2; j++) {
        int octet = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
        String hex = Integer.toHexString(octet);
        address += hex + ":";
      }
      address = address.substring(0, address.length() - 1);
      InetAddress addr = null;
      try {
        addr = InetAddress.getByName(address);
        record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, addr);
        verbosePrintResourceRecord(record, 0);
      } catch (UnknownHostException e){
        errorOccured = true;
      }
    } else if (typeCode == 2 || typeCode == 5 || typeCode == 6) { // NS or CNAME or SOA
      String data = getNameFromPointer(responseBuffer, pointer);
      record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, data);
      verbosePrintResourceRecord(record, 0);
    }
    else { // all other types are assumed to have value like NS or CNAME
      String data = getNameFromPointer(responseBuffer, pointer);
      record = new ResourceRecord(hostName, RecordType.getByCode(typeCode), TTL, data);
      verbosePrintResourceRecord(record, 0);
    }

    if (!errorOccured) {
      cache.addResult(record);
    }
    return record;
  }
    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */

   public static Set<ResourceRecord> decodeAndCacheResponse(int queryID, DNSNode node, byte[] responseBuffer) {
    int responseID = getIntFromTwoBytes(responseBuffer[0],responseBuffer[1]);
    int QR = (responseBuffer[2] & 0x80) >>> 7; // get 1st bit
    int opCode = (responseBuffer[2] & 0x78) >>> 3; // get 2nd, 3rd, 4th and 5th bit
    int AA = (responseBuffer[2] & 0x04) >>> 2; // geth 6th
    int TC = (responseBuffer[2] & 0x02) >>> 1; // get 7th bit
    int RD = responseBuffer[2] & 0x01; // get 8th bit

    if (verboseTracing)
      System.out.println("Response ID: " + responseID + " Authoritative = " + (AA == 1));

    int RA = responseBuffer[3] & 0x80;
    int RCODE = responseBuffer[3] & 0x0F;
    String message = "";
    switch (RCODE) {
      case 0: message = "OK. No error on RCODE";
          break;
      case 1: message = "FAILED. Format error, name server didn't understand query";
          break;
      case 2: message = "FAILED. Server error";
          break;
      case 3: message = "FAILED. Name error – the name doesn't exist";
          break;
      case 4: message = "FAILED. Support for query not implemented";
          break;
      case 5: message = "FAILED. Request refused";
          break;
      default: message = "FAILED. Unknown RCODE";
          break;
    }

    int QDCOUNT = getIntFromTwoBytes(responseBuffer[4], responseBuffer[5]);
    int ANCOUNT = getIntFromTwoBytes(responseBuffer[6], responseBuffer[7]);
    int NSCOUNT = getIntFromTwoBytes(responseBuffer[8], responseBuffer[9]);
    int ARCOUNT = getIntFromTwoBytes(responseBuffer[10], responseBuffer[11]);
    pointer = 12;
    String receivedQNAME = "";
    while(true) {
      int labelLength = responseBuffer[pointer++] & 0xFF;
      if (labelLength == 0)
        break;
      for (int i = 0; i < labelLength; i++) {
        char ch = (char) (responseBuffer[pointer++] & 0xFF);
        receivedQNAME += ch;
      }
      receivedQNAME += '.';
    }
    //receivedQNAME = receivedQNAME.substring(0, receivedQNAME.length() - 1);
    int QTYPE = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);
    int QCLASS = getIntFromTwoBytes(responseBuffer[pointer++], responseBuffer[pointer++]);

    ResourceRecord record = null;

    if (verboseTracing)
      System.out.println("  Answers (" + ANCOUNT + ")");
    for (int i=0; i < ANCOUNT; i++) {
      decodeSingleRecord(responseBuffer);
    }

    ArrayList<ResourceRecord> nameServers = new ArrayList<ResourceRecord>();
    if (verboseTracing)
      System.out.println("  Nameservers (" + NSCOUNT + ")");
    for (int i=0; i < NSCOUNT; i++) {
      record = decodeSingleRecord(responseBuffer);
      if (record != null) {
        nameServers.add(record);
      }
    }

    ArrayList<ResourceRecord> additionals = new ArrayList<ResourceRecord>();
    if (verboseTracing)
      System.out.println("  Additional Information (" + ARCOUNT + ")");
    for (int i=0; i < ARCOUNT; i++) {
      record = decodeSingleRecord(responseBuffer);
      if (record != null) {
        additionals.add(record);
      }
    }

    if (AA == 1 || RCODE != 0){
      return null;
    } else { // AA = 0 case
      Set<ResourceRecord> resourceRecords = new HashSet<ResourceRecord>();
      for (ResourceRecord nameserver: nameServers) {
        String name = nameserver.getTextResult();
        for (ResourceRecord additional: additionals) {
          if (additional.getHostName().equals(name) && additional.getType().getCode() == 1){
            // A records for name servers
            resourceRecords.add(additional);
          }
        }
      }
      if (resourceRecords.isEmpty()){
        for (ResourceRecord nameserver: nameServers) {
          String name = nameserver.getTextResult();
          // search for nameserver A record
          DNSNode nsServerNode = new DNSNode(name, RecordType.getByCode(1));
          Set<ResourceRecord> newResults = DNSLookupService.getResults(nsServerNode, 0);
          if (!newResults.isEmpty()){
            resourceRecords.addAll(newResults);
            break;
          }
        }
      }
      return resourceRecords; 
    }
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

