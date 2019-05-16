package unimelb.bitbox.util;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

public class CommandLineArgument {
    @Option(name = "-c", required = true, usage="Command")
    public String command;

    @Option(name = "-s", required = true, usage="Server")
    public String server;

    @Option(name = "-p", usage="Peer")
    public String peer;

    @Option(name = "-i", usage="Identity")
    public String identity;

    public String getCommand() {
        return command;
    }

    public String getServer() {
        return server;
    }

    public String getPeer() {
        return peer;
    }

    public String getIdentity() {
        return identity;
    }

    //Just for testing
    public static void main(String[] args) {
        for (int index = 0 ; index < args.length; index ++)
            System.out.println(args[index]);
        System.exit(new CommandLineArgument().run(args));
    }

    private int run(String[] args) {
        CmdLineParser p = new CmdLineParser(this);
        try {
            p.parseArgument(args);
            run();
            return 0;
        } catch (CmdLineException e) {
            System.err.println(e.getMessage());
            p.printUsage(System.err);
            return 1;
        }
    }

    // Just for testing
    private void run() {
        System.out.format("java -cp bitbox.jar unimelb.bitbox.Client -c %s -s %s -p %s\n", command, server, peer);
    }
}
