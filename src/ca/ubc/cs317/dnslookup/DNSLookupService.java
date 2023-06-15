package ca.ubc.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;

import ca.ubc.cs317.dnslookup.DNSNode;
import ca.ubc.cs317.dnslookup.RecordType;
import ca.ubc.cs317.dnslookup.ResourceRecord;

public class DNSLookupService {

    private static boolean p1Flag = false; // isolating part 1
    private static final int MAX_INDIRECTION_LEVEL = 10;
    private static InetAddress rootServer;
    private static DNSCache cache = DNSCache.getInstance();
    private static int nsDiscontinuedFlag = 0;
    private static DNSNode nsDiscontinuedNode = null;
    private static int emptyNSFlag = 0;

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length == 2 && args[1].equals("-p1")) {
            p1Flag = true;
        } else if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println(
                    "where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            DNSQueryHandler.openSocket();
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("317LOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null)
                break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty())
                continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") || commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    boolean verboseTracing = false;
                    if (commandArgs[1].equalsIgnoreCase("on")) {
                        verboseTracing = true;
                        DNSQueryHandler.setVerboseTracing(true);
                    } else if (commandArgs[1].equalsIgnoreCase("off")) {
                        DNSQueryHandler.setVerboseTracing(false);
                    } else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") || commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup [fqdn] [type]");
                System.err.println("\ttrace [on|off]");
                System.err.println("\tserver [IP]");
                System.err.println("\tdump");
                System.err.println("\tquit");
            }

        } while (true);

        DNSQueryHandler.closeSocket();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard
     * output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the results for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to
     *                         CNAME redirection. The initial call should be made
     *                         with 0 (zero), while recursive calls for regarding
     *                         CNAME results should increment this value by 1. Once
     *                         this value reaches MAX_INDIRECTION_LEVEL, the
     *                         function prints an error message and returns an empty
     *                         set.
     * @return A set of resource records corresponding to the specific query
     *         requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (p1Flag) { // For isolating part 1 testing only
            retrieveResultsFromServer(node, rootServer);
            return Collections.emptySet();
        } else if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        // looking for exact matches
        Set<ResourceRecord> resRecords = cache.getCachedResults(node);
        if (resRecords.size() != 0) {
            emptyNSFlag = 0;
            return resRecords;
        }
        // looking for possible situation
        else {
            // cname
            DNSNode cnameNode = new DNSNode(node.getHostName(), RecordType.CNAME);
            if (!cache.getCachedResults(cnameNode).isEmpty()) {
                ResourceRecord cRecord = cache.getCachedResults(cnameNode).iterator().next();
                DNSNode cNode_A = new DNSNode(cRecord.getTextResult(), node.getType());
                emptyNSFlag = 0;
                resRecords = getResults(cNode_A, indirectionLevel+1);
                return resRecords;
            }
            // ns discontinue
            if (nsDiscontinuedFlag == 1) {
                nsDiscontinuedFlag = 0;
                DNSNode nsNode = nsDiscontinuedNode;
                nsDiscontinuedNode = null;
                emptyNSFlag = 0;
                Set<ResourceRecord> nsRecords = getResults(nsNode, indirectionLevel);
                if (nsRecords.isEmpty()) {
                    return Collections.emptySet();
                }
                retrieveResultsFromServer(node, nsRecords.iterator().next().getInetResult());
                resRecords = getResults(node, indirectionLevel);
                return resRecords;
            }
            // simply empty
            if (emptyNSFlag == 1) {
                emptyNSFlag = 0;
                return Collections.emptySet();
            }
            // decrement hostname, look for possible match
            Set<ResourceRecord> nameservers = Collections.emptySet();
            DNSNode tempNode = node;
            int baseflag = 0;

            while (nameservers.size() == 0) {
                // Not found in cache
                if (getDNSNodeLevel(tempNode) == 1) {
                    // base case
                    baseflag = 1;
                    retrieveResultsFromServer(node, rootServer);
                    // resRecords = cache.getCachedResults(rootNode);
                    break;
                } else {
                    // decrement hostname to check if we have a cache hit
                    DNSNode prev_level_NS = new DNSNode(decrementHostName(tempNode.getHostName()), RecordType.NS);
                    nameservers = cache.getCachedResults(prev_level_NS);
                    tempNode = prev_level_NS;
                }
            }

            if (baseflag != 1) {
                queryNextLevel(node, nameservers);
            }
            resRecords = getResults(node, indirectionLevel);

            return resRecords;
        }

    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in
     * iterative mode, and the query is repeated with a new server if the provided
     * one is non-authoritative. Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        byte[] message = new byte[512]; // query is no longer than 512 bytes

        try {
            DNSServerResponse serverResponse = DNSQueryHandler.buildAndSendQuery(message, server, node);

            Set<ResourceRecord> nameservers = DNSQueryHandler.decodeAndCacheResponse(serverResponse.getTransactionID(),
                    serverResponse.getResponse(), cache);
            if (nameservers == null)
                nameservers = Collections.emptySet();

            if (p1Flag) return; // For testing part 1 only
            
            queryNextLevel(node, nameservers);

        } catch (IOException | NullPointerException ignored) {
            // Get no response, return emptyflag
            emptyNSFlag = 1;
        }
    }

    /**
     * Query the next level DNS Server, if necessary
     *
     * @param node        Host name and record type of the query.
     * @param nameservers List of name servers returned from the previous level to
     *                    query the next level.
     */
    private static void queryNextLevel(DNSNode node, Set<ResourceRecord> nameservers) {
        // empty nameservers
        if (nameservers.isEmpty()) {
            emptyNSFlag = 1;
            return;
        }
        // find the exact matching
        if (!cache.getCachedResults(node).isEmpty()) {
            return;
        }
        // otherwise query the next level

        // traverse each ns, until find a ns has additional info provided.
        // if no additonal info is found, then we will set the nsDiscontinuedFlag.
        Iterator<ResourceRecord> it = nameservers.iterator();
        while (it.hasNext()) {
            ResourceRecord oneNSRecord = it.next();
            DNSNode NSRecord_A = new DNSNode(oneNSRecord.getTextResult(), RecordType.A);
            Set<ResourceRecord> ARecords = cache.getCachedResults(NSRecord_A);
            InetAddress server;
            if (ARecords.size() == 0) {
                continue;
            } else {
                    // perform the query to get the final result
                    server = ARecords.iterator().next().getInetResult();
                    retrieveResultsFromServer(node, server);
                    return;
            }
        }
        // no additional info provided, query root server the NS
        nsDiscontinuedFlag = 1;
        ResourceRecord oneNSRecord = nameservers.iterator().next();
        DNSNode NSRecord_A = new DNSNode(oneNSRecord.getTextResult(), RecordType.A);
        nsDiscontinuedNode = NSRecord_A;
        return;

    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(), node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(), node.getType(), record.getTTL(),
                    record.getTextResult());
        }
    }

    private static String decrementHostName(String hostName) {
        String[] hostNameArr = hostName.split("\\.");
        String[] reducedHostNameArr = Arrays.copyOfRange(hostNameArr, 1, hostNameArr.length);
        hostName = String.join(".", reducedHostNameArr);
        return hostName;
    }

    private static int getDNSNodeLevel(DNSNode node) {
        String hostName = node.getHostName();
        String[] hostNameArr = hostName.split("\\.");
        return hostNameArr.length;
    }
}
