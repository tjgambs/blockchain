/*--------------------------------------------------------

1. Name / Date: Tim Gamble / 2017-10-29

2. Java version used, if not the official version for the class: build 1.8.0_144-b01

3. Precise command-line compilation examples / instructions:

> javac Blockchain.java

4. Precise examples / instructions to run this program:

In separate shell windows:

> java Blockchain 0
> java Blockchain 1
> java Blockchain 2

5. List of files needed for running the program.

e.g.:

 a. Blockchain.java

5. Notes:

I have print lines explaining how to use the reading, listing and verifying options.
However, here they are as well:
    R <filename> - Have this process head in the filename and emit all of its data as
                    unveriefied blocks to the network.
    L - List the state of the current blockchain
    V - Verify the blockchain, confirming it is valid

You can emulate an error in verification by putting <hash,signature,threshold> after the V.

----------------------------------------------------------*/


import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.File;
import java.io.FileWriter;
import java.io.StringWriter;
import java.io.StringReader;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.text.*;
import java.net.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;


@XmlRootElement
class BlockRecord{
    /* Block record class that contains all the information about each
    block in the block chain. In this class we have a marshalling system
    such that it is easy to convert this class to and from XML.
    */
    String SHA256String;
    String SignedSHA256;
    String BlockID;
    String SignedBlockID;
    String VerificationProcessID;
    String CreatingProcess;
    String Fname;
    String Lname;
    String SSNum;
    String DOB;
    String Diag;
    String Treat;
    String Rx;
    String ACreatedAt;
    String AVerifiedAt;
    String ADataHash;
    String ASignedDataHash;
    String ARandomSeedString;
    String ABlockNum;

    public boolean isTheSameBlock(BlockRecord b) {
        /* Given another block, return true if this and the block share the
        same data. */
        return (this.SHA256String.equals(b.SHA256String)
                 && this.SignedSHA256.equals(b.SignedSHA256)
                 && this.BlockID.equals(b.BlockID)
                 && this.SignedBlockID.equals(b.SignedBlockID)
                 && this.VerificationProcessID.equals(b.VerificationProcessID)
                 && this.CreatingProcess.equals(b.CreatingProcess)
                 && this.Fname.equals(b.Fname)
                 && this.Lname.equals(b.Lname)
                 && this.SSNum.equals(b.SSNum)
                 && this.SSNum.equals(b.DOB)
                 && this.SSNum.equals(b.Diag)
                 && this.SSNum.equals(b.Treat)
                 && this.SSNum.equals(b.Rx)
                 && this.SSNum.equals(b.ACreatedAt)
                 && this.SSNum.equals(b.AVerifiedAt)
                 && this.SSNum.equals(b.ADataHash)
                 && this.SSNum.equals(b.ASignedDataHash)
                 && this.SSNum.equals(b.ARandomSeedString)
                 && this.SSNum.equals(b.ABlockNum));
    }

    public String getABlockNum() {return ABlockNum;}
    @XmlElement
        public void setABlockNum(String BN){this.ABlockNum = BN;}

    public String getASHA256String() {return SHA256String;}
    @XmlElement
        public void setASHA256String(String SH){this.SHA256String = SH;}

    public String getASignedSHA256() {return SignedSHA256;}
    @XmlElement
        public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}

    public String getACreatingProcess() {return CreatingProcess;}
    @XmlElement
        public void setACreatingProcess(String CP){this.CreatingProcess = CP;}

    public String getAVerificationProcessID() {return VerificationProcessID;}
    @XmlElement
        public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}

    public String getABlockID() {return BlockID;}
    @XmlElement
        public void setABlockID(String BID){this.BlockID = BID;}

    public String getASignedBlockID() {return SignedBlockID;}
    @XmlElement
        public void setASignedBlockID(String SBID){this.SignedBlockID = SBID;}

    public String getFSSNum() {return SSNum;}
    @XmlElement
        public void setFSSNum(String SS){this.SSNum = SS;}

    public String getFFname() {return Fname;}
    @XmlElement
        public void setFFname(String FN){this.Fname = FN;}

    public String getFLname() {return Lname;}
    @XmlElement
        public void setFLname(String LN){this.Lname = LN;}

    public String getFDOB() {return DOB;}
    @XmlElement
        public void setFDOB(String DOB){this.DOB = DOB;}

    public String getGDiag() {return Diag;}
    @XmlElement
        public void setGDiag(String D){this.Diag = D;}

    public String getGTreat() {return Treat;}
    @XmlElement
        public void setGTreat(String D){this.Treat = D;}

    public String getGRx() {return Rx;}
    @XmlElement
        public void setGRx(String D){this.Rx = D;}

    public String getACreatedAt() {return ACreatedAt;}
    @XmlElement
        public void setACreatedAt(String T) {this.ACreatedAt = T;}

    public String getAVerifiedAt() {return AVerifiedAt;}
    @XmlElement
        public void setAVerifiedAt(String T) {this.AVerifiedAt = T;}

    public String getADataHash() {return ADataHash;}
    @XmlElement
        public void setADataHash(String D) {this.ADataHash = D;}

    public String getASignedDataHash() {return ASignedDataHash;}
    @XmlElement
        public void setASignedDataHash(String D) {this.ASignedDataHash = D;}

    public String getARandomSeedString() {return ARandomSeedString;}
    @XmlElement
        public void setARandomSeedString(String RSS) {this.ARandomSeedString = RSS;}
}


class BlockChainServer implements Runnable {

    public boolean LISTENING = true;
    private DatagramSocket socket = null;
    private UnverifiedBlockServer unverifiedBlockServer;
    public LinkedList<BlockRecord> blockChain;
    public ArrayList<String> blockChainBlockIds;
    private int pid;

    public BlockChainServer(int port, UnverifiedBlockServer unverifiedBlockServer, int pid) {
        /* We use the UDP protocol so we set up a Datagram socket for 
        sending and receiving data to and from this thread. We also store the
        unverified block server object reference so we can send and read data to that object.
        We also initialize the blockchain as an empty ledger.
        */
        try {
            this.socket = new DatagramSocket(port);
        } catch (SocketException e) {}
        this.unverifiedBlockServer = unverifiedBlockServer;
        this.blockChain = new LinkedList<BlockRecord>();
        this.blockChainBlockIds = new ArrayList<String>();
        this.pid = pid;
    }

    public void run() {
        /* This function runs for the lifetime of the thread. First, we 
        set up a byte array which will be responsible for storing the 
        datagram packets being sent to our socket. Inside of the running loop, 
        we receive all packets that are being sent to the socket. I assume that
        if data is being sent to this socket that it is a new block chain attempting
        to be multicasted to the network. As such, I send this data to the 
        updateblockchain method. If the process id of this process is 0, then it 
        must write the contents of the block chain to a file.
        */
        byte[] request = new byte[102400];
        DatagramPacket requestPacket = new DatagramPacket(request, request.length);
        while (LISTENING) {
            try {
                this.socket.receive(requestPacket);
            } catch (Exception e) {}
            String payload = new String(request, 0, requestPacket.getLength());
            this.updateBlockChain(payload);
            if (this.pid == 0) {
                this.writeBlockChain(payload);
            }
        }
    }

    public void writeBlockChain(String newBlockChainString) {
        /* Given a block chain as represented by a String, write the contents to
        a file. */
        try {
            FileWriter fw = new FileWriter(new File("BlockchainLedger.xml"));
            fw.write(newBlockChainString);
            fw.flush();
            fw.close();
        } catch (Exception e) {}
    }

    public void listBlockChain() {
        /* When the user asks to list the current block chain, we list everything but the
        genesis block. */
        for (int i = this.blockChain.size()-1; i > 0; i--) {
            BlockRecord block = this.blockChain.get(i);
            System.out.println(block.getABlockNum() + ". " + block.getAVerifiedAt() + " " + 
                                block.getFFname() + " " + block.getFLname() + " " + 
                                block.getFDOB() + " " + block.getFSSNum() + " " + 
                                block.getGDiag() + " " + block.getGRx());
        }
    }

    public void verifyBlockChain(int flag) {
        /* Verify the entire block chain when the user asks. */
        int P0 = 0;
        int P1 = 0;
        int P2 = 0;
        for (int i = 1; i < this.blockChain.size(); i++) {
            try {
                BlockRecord pBlock = this.blockChain.get(i-1);
                BlockRecord cBlock = this.blockChain.get(i);
                /* Credit is given to nodes for validating blocks */
                String verifier = cBlock.getAVerificationProcessID();
                if (verifier.equals("Process0")) P0++;
                if (verifier.equals("Process1")) P1++;
                if (verifier.equals("Process2")) P2++;
                /* Verify that the SHA-256-String in the current block's header matches the hash just produced. */
                BlockRecord copy = new BlockRecord();
                copy.setABlockID(cBlock.getABlockID());
                copy.setABlockNum(cBlock.getABlockNum());
                copy.setACreatedAt(cBlock.getACreatedAt());
                copy.setACreatingProcess(cBlock.getACreatingProcess());
                copy.setADataHash(cBlock.getADataHash());
                copy.setARandomSeedString(cBlock.getARandomSeedString());
                copy.setASignedBlockID(cBlock.getASignedBlockID());
                copy.setASignedDataHash(cBlock.getASignedDataHash());
                copy.setFDOB(cBlock.getFDOB());
                copy.setFFname(cBlock.getFFname());
                copy.setFLname(cBlock.getFLname());
                copy.setFSSNum(cBlock.getFSSNum());
                copy.setGDiag(cBlock.getGDiag());   
                copy.setGRx(cBlock.getGRx());
                copy.setGTreat(cBlock.getGTreat());
                StringWriter sw = new StringWriter();
                JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
                Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
                jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
                jaxbMarshaller.marshal(copy, sw);
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                String blockXML = sw.toString();
                md.update((blockXML + pBlock.getASHA256String()).getBytes());
                byte[] byteData = md.digest();
                StringBuffer sb = new StringBuffer();
                for (int j = 0; j < byteData.length; j++) {
                    sb.append(Integer.toString((byteData[j] & 0xff) + 0x100, 16).substring(1));
                }
                String SHA256String = sb.toString();
                if (!cBlock.getASHA256String().equals(SHA256String) || flag == 1) {
                    System.out.println("Block "+cBlock.getABlockNum()+" invalid: sha256 hash does not match.");
                }
                /* Validate the Signed-SHA56 signature using the public key of the verifying process. */
                PublicKey verificationPublicKey = this.unverifiedBlockServer.blockVerifier.publicKeys.get(cBlock.getAVerificationProcessID());
                byte[] decodedSignedSHA256 = Base64.getDecoder().decode(cBlock.getASignedSHA256());
                boolean verifiedSHA256 = this.unverifiedBlockServer.blockVerifier.verifySig(cBlock.getASHA256String().getBytes(),verificationPublicKey,decodedSignedSHA256);
                if (!verifiedSHA256 || flag == 2) {
                    System.out.println("Block "+cBlock.getABlockNum()+" invalid: signed sha256 string does not match verifying process");
                }
                /* Validate the Signed-BlockId using the public key of the creating process. */
                PublicKey creationPublicKey = this.unverifiedBlockServer.blockVerifier.publicKeys.get(cBlock.getACreatingProcess());
                byte[] decodedSignedBlockID = Base64.getDecoder().decode(cBlock.getASignedBlockID());
                boolean verifiedBlockID = this.unverifiedBlockServer.blockVerifier.verifySig(cBlock.getABlockID().getBytes(),creationPublicKey,decodedSignedBlockID);
                if (!verifiedBlockID || flag == 1) {
                    System.out.println("Block "+cBlock.getABlockNum()+" invalid: signed block id does not match creating process");
                }
                /* Validate that the work threshold has been met */
                StringBuffer sb1 = new StringBuffer();
                for (int j = 0; j < 4; j++) {
                    sb1.append(Integer.toBinaryString((byteData[j] & 0xFF) + 0x100).substring(1));
                }
                Long t = Long.parseLong(sb1.toString(), 2);
                if (t >= 50000 || flag == 3) {
                    System.out.println("Block "+cBlock.getABlockNum()+" invalid: SHA256 confirmed, but does not meet the work threshold");
                }
                flag = 0;
            } catch (Exception e) {}
        }
        System.out.println("Blocks 1-"+(this.blockChain.size()-1)+" in the blockchain have been verified. Credit: P0="+P0+",P1="+P1+", P2="+P2);
    }

    public BlockRecord createBlock(String xml) {
        /* Given a xml of a BlockRecord, convert it back into a BlockRecord object */
        StringReader reader = new StringReader(xml);
        BlockRecord blockRecord = null;
        JAXBContext jaxbContext = null;
        Unmarshaller jaxbUnmarshaller = null;
        try {
            jaxbContext = JAXBContext.newInstance(BlockRecord.class);
            jaxbUnmarshaller = jaxbContext.createUnmarshaller();
            blockRecord = (BlockRecord) jaxbUnmarshaller.unmarshal(reader);
        } catch (JAXBException e) {}
        return blockRecord;
    }

    public void updateBlockChain(String newBlockChainString) {

        /* The purpose of this function is to ingest a new blockchain 
        represented as xml and convert it into an list of blocks. 
        Along the way, I also keep track of the block Ids for constant 
        time lookup of existence later on. Before updating the ledger and 
        multicasting it, I want to make sure that this block chain is of 
        larger length of the current block chain otherwise this 'new' 
        version is actually out of date.
        */
        String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";
        String cleanedXml = newBlockChainString.replace(XMLHeader,"")
                                                .replace("<BlockLedger>","")
                                                .replace("</BlockLedger>","");
        LinkedList<BlockRecord> newBlockChain = new LinkedList<BlockRecord>();
        ArrayList<String> newBlockChainBlockIds = new ArrayList<String>();
        for (String b: cleanedXml.split("\n\n")) {
            BlockRecord block = this.createBlock(XMLHeader + b);
            if (block != null) {
                newBlockChain.add(block);
                newBlockChainBlockIds.add(block.getABlockID());
            }
        }

        if (this.blockChain.size() == newBlockChain.size()) {
            /* Iterate through the block chain until it reaches a nonidentical block */
            int i;
            for (i = 1; i < this.blockChain.size(); i++) {
                if(!this.blockChain.get(i).isTheSameBlock(newBlockChain.get(i))) {
                    break;
                }
            }
            if (this.blockChain.get(i).getABlockID() == newBlockChain.get(i).getABlockID()) {
                //TODO: Same length / same blockID / different timestamp handled          
            } else {
                //TODO: Same length / different blockID handled 
            }
        } else if (this.blockChain.size() < newBlockChain.size()) {
            this.blockChain = newBlockChain;
            this.blockChainBlockIds = newBlockChainBlockIds;
            this.unverifiedBlockServer.updateBlockChain(this.blockChain, 
                                                this.blockChainBlockIds);
        }
    }
}


class BlockVerifier extends Thread {

    public boolean COMPUTING = true;
    public LinkedList<BlockRecord> blockChain;
    public ArrayList<String> blockChainBlockIds;
    private Queue<BlockRecord> unverifiedBlocks;
    private DatagramSocket socket;
    private int pid;
    public HashMap<String,PublicKey> publicKeys;
    public KeyPair keyPair;

    public BlockVerifier(DatagramSocket socket, int pid, KeyPair keyPair) {
        this.socket = socket;
        this.pid = pid;
        this.keyPair = keyPair;
        this.unverifiedBlocks = new LinkedList<BlockRecord>();
        this.blockChain = new LinkedList<BlockRecord>();
        BlockRecord initBlock = new BlockRecord();
        initBlock.setABlockID("32feffc5-1eec-4c16-ac75-09d5fe40933e");
        initBlock.setABlockNum("0");
        initBlock.setASHA256String("aSF9WoOCB+ZnsR91Q57ahdyuJ7y+i9IW9yN40flawx8=");
        this.blockChain.add(initBlock);
        this.blockChainBlockIds = new ArrayList<String>();
        this.blockChainBlockIds.add("32feffc5-1eec-4c16-ac75-09d5fe40933e");
        this.publicKeys = new HashMap<String,PublicKey>();
    }

    public void addBlock(String block) {
        /* Given a xml representation of a block, transform it into a 
        BlockRecord and add it to the unverified block queue. 
        */
        BlockRecord newBlock = this.createBlock(block);
        if (newBlock != null) {
            this.unverifiedBlocks.add(newBlock);
        }
    }

    public BlockRecord createBlock(String xml) {
        /* Given a xml of a BlockRecord, convert it back into a BlockRecord object */
        StringReader reader = new StringReader(xml);
        BlockRecord blockRecord = null;
        JAXBContext jaxbContext = null;
        Unmarshaller jaxbUnmarshaller = null;
        try {
            jaxbContext = JAXBContext.newInstance(BlockRecord.class);
            jaxbUnmarshaller = jaxbContext.createUnmarshaller();
            blockRecord = (BlockRecord) jaxbUnmarshaller.unmarshal(reader);
        } catch (JAXBException e) {}
        return blockRecord;
    }

    public void updateBlockChain(LinkedList<BlockRecord> newBlockChain, 
                                    ArrayList<String> newBlockChainBlockIds) {
        /* Just a setter for the new block chain */
        this.blockChainBlockIds = newBlockChainBlockIds;
        this.blockChain = newBlockChain;
    }

    public void run() {
        /* This function runs for the lifetime of the thread. I continually 
        check to see if the queue of unverified blocks is not empty. The 
        moment the queue has an unverified block, I begin attempting to solve 
        the work problem (in this case it is faked). While attempting the work, 
        I continually check to see if the block chain current has the block id. 
        The moment the block chain has the id, I move on to the next unverified 
        block, if it exists.
        */
        while (COMPUTING) {
            if (!this.unverifiedBlocks.isEmpty()) {
                /* Pull out a block record from the queue */
                BlockRecord block = unverifiedBlocks.remove();
                /* First, verify that the signed block ID made by the creator of the block ID. */
                PublicKey publicKey = this.publicKeys.get(block.getACreatingProcess());
                byte[] decodedSignedBlockID = Base64.getDecoder().decode(block.getASignedBlockID());
                boolean verifiedBlockID = this.verifySig(block.getABlockID().getBytes(),publicKey,decodedSignedBlockID);
                if (!verifiedBlockID)
                    continue;
                /* Second, get the last block from the block chain. */
                BlockRecord lastBlock = this.blockChain.getLast();
                /* Using the last block, update this block's blockNum by adding one to the last blockNum. */
                Integer blockID = Integer.valueOf(lastBlock.getABlockNum())+1;
                block.setABlockNum(blockID.toString());
                /* Using the last block, pull out its SHA256 String to use in the creation of this SHA256 String */
                String previousSHA256 = lastBlock.getASHA256String();

                String blockId = block.getABlockID();
                try {          
                    JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
                    Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
                    jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
                    /* Convert the object to xml and generate a SHA256 string that represents 
                    that string of text. 
                    Items in XML:
                        - BlockNum
                        - BlockID
                        - SignedBlockID
                        - Creating Process
                        - Creation time
                        - First Name
                        - Last Name
                        - Date of Birth
                        - SSN
                        - Diagnosis
                        - Tratment
                        - Medecine
                        - Random String
                        - Previous SHA256
                    */    
                    byte[] a = new byte[256];
                    Random r1 = new Random();   
                    while (true) {
                        /* Fill the byte array with random bytes, then get its string value. */
                        r1.nextBytes(a);
                        /* Update the block with a random string */
                        StringWriter sw = new StringWriter();
                        block.setARandomSeedString(Base64.getEncoder().encodeToString(a));
                        jaxbMarshaller.marshal(block, sw);
                        String blockXML = sw.toString();

                        /* Get a byte array that represents the blockXML plus a random SHA256 String. */
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        md.update((blockXML + previousSHA256).getBytes());
                        byte[] byteData = md.digest();
                        /* Look at the last 4 bytes of the array (32 bits) and get its binary representation
                        such that we can convert the 32 bits into an integer. */
                        StringBuffer sb = new StringBuffer();
                        for (int i = 0; i < 4; i++) {
                            sb.append(Integer.toBinaryString((byteData[i] & 0xFF) + 0x100).substring(1));
                        }
                        Long t = Long.parseLong(sb.toString(), 2);
                        if (t < 50000) {
                            /* From the SHA256 string, generate a signed string. */
                            StringBuffer sb1 = new StringBuffer();
                            for (int i = 0; i < byteData.length; i++) {
                                sb1.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
                            }
                            String SHA256String = sb1.toString();
                            byte[] digitalSignature = this.signData(SHA256String.getBytes());
                            String SignedSHA256 = Base64.getEncoder().encodeToString(digitalSignature);
                            /* Set the SHA256 String, the signed SHA 256 string this process id and a timestamp. 
                            Afterwards, we add the block to the block chain then multicast it to all
                            participating processes in the network. */
                            block.setASHA256String(SHA256String);
                            block.setASignedSHA256(SignedSHA256);
                            block.setAVerificationProcessID("Process" + this.pid);
                            Date date = new Date();
                            String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                            block.setAVerifiedAt(T1 + "." + this.pid);
                            this.blockChain.add(block);
                            this.multicastNewBlockchain(blockId);
                            break;
                        }
                        if (this.blockChainBlockIds.contains(blockId)) {
                            break;
                        }
                    }
                } catch(Exception e) {}
            }
            System.out.flush();
        }
    }

    public boolean verifySig(byte[] data, PublicKey key, byte[] sig) {
        /* Verify that applying the public key to the data verifies
        the signature. Basically, was this data signed with the private
        key of this public key? */
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(key);
            signer.update(data);
            return (signer.verify(sig));
        } catch (Exception e) {
            return false;
        }
    }

    public byte[] signData(byte[] data) {
        /* Given a byte array of data, use the private key of this process and
        sign the data such that only the public key can decode it to get the
        original data. */
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(this.keyPair.getPrivate());
            signer.update(data);
            return (signer.sign());
        } catch (Exception e) {
            return null;
        }
    }

    private void multicastNewBlockchain(String blockId) {
        /* Take the current state of the block chain, transform it into xml that can be 
        sent through sockets. We convert the xml to bytes to send within a datagram. We
        hard coded the ip address and port numbers of the servers accepting new block 
        chains to make things easier.
        */
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            StringWriter sw = new StringWriter();
            for (int i = 0; i < this.blockChain.size(); i++){
                jaxbMarshaller.marshal(this.blockChain.get(i), sw);
            }
            String fullBlock = sw.toString();
            String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
            String cleanBlock = fullBlock.replace(XMLHeader, "");
            String XMLBlock = XMLHeader + "\n<BlockLedger>" + cleanBlock + "</BlockLedger>";
            byte[] data = XMLBlock.getBytes();
            InetAddress theirIpAddress = InetAddress.getLocalHost();
            int[] theirPortNumbers = {4810, 4811, 4812};
            if (!this.blockChainBlockIds.contains(blockId)) { //One last check to make sure
                for (int theirPortNumber: theirPortNumbers) {
                    DatagramPacket packet = new DatagramPacket(data,data.length,
                                                    theirIpAddress,theirPortNumber);
                    this.socket.send(packet);
                }
            }
        } catch (Exception e) {} 
    }
}


class UnverifiedBlockServer implements Runnable {

    public boolean LISTENING = true;
    private DatagramSocket socket = null;
    public BlockVerifier blockVerifier;
    public KeyPair keyPair;
    private int pid;
    public boolean ready;

    public UnverifiedBlockServer(int port, int pid) {
        /* We use the UDP protocol so we set up a DataGram socket for 
        sending and receiving data to and from this thread.
        */
        try {
            this.socket = new DatagramSocket(port);
        } catch (SocketException e) {}
        this.keyPair = generateKeyPair();
        this.pid = pid;
        this.blockVerifier = new BlockVerifier(this.socket, this.pid, this.keyPair); 
        if (this.pid == 2) {
            this.multicast("multicast keys");    
        }
        this.ready = false;
    }

    public static KeyPair generateKeyPair() {
        /* Generate a public and private key pair. 
        This code was provided by our Professor.
        */
        KeyPairGenerator keyGenerator = null;
        SecureRandom rng = null;
        try {
            keyGenerator = KeyPairGenerator.getInstance("RSA");
            rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (Exception e) {}
        keyGenerator.initialize(1024, rng);
        return (keyGenerator.generateKeyPair());
      }

    public void updateBlockChain(LinkedList<BlockRecord> newBlockChainString, 
                                    ArrayList<String> newBlockChainBlockIds) {
        /* Every time a new block chain is sent out, it makes its 
        way to this function which is in charge of sending it to 
        the thread that actually needs it.
        */
        this.blockVerifier.updateBlockChain(newBlockChainString,
                                        newBlockChainBlockIds);
    }

    public void run() {
        /* This function runs for the lifetime of the thread. First, we 
        set up a byte array which will be responsible for storing the 
        datagram packets being sent to our socket. Then we start up a new 
        thread whose sole purpose is to verify blocks.
        Inside of the running look, we receive all packets that are being 
        sent to the socket. If the word "blockrecord" is within this record
        then I assume that this data is a new, unverified block. With this 
        assumption, I add the unverified block to the queue for the verification
        thread to consume when possible. 
        */
        byte[] request = new byte[102400];
        DatagramPacket requestPacket = new DatagramPacket(request, request.length);
        new Thread(this.blockVerifier).start();
        while (LISTENING) {
            try {      
                this.socket.receive(requestPacket);
            } catch (IOException e) {} 
            String payload = new String(request, 0, requestPacket.getLength());
            if (payload.toLowerCase().indexOf("blockrecord") > -1) {
                this.blockVerifier.addBlock(payload);
            } else if (payload.indexOf("multicast keys") > -1) {
                /* This is the message that we will receive from process 2 when it wants
                everyone to share their public keys. */
                System.out.println("Emiting process " + this.pid + " public key");
                String data = "public key: Process" + this.pid + "|" +  
                    Base64.getEncoder().encodeToString(this.keyPair.getPublic().getEncoded());
                this.multicast(data);
            } else if (payload.indexOf("public key: ") > -1) {
                String[] data = payload.replace("public key: ","").split("[|]"); 
                /* Because, I sent the public key over the network as a base64 string, 
                I must decode it back into a byte array and using a Key Factory I convert the 
                byte array into a public key.*/     
                try {
                    byte[] decodedCreatorPublicKey = Base64.getDecoder().decode(data[1]);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedCreatorPublicKey);
                    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);
                    this.blockVerifier.publicKeys.put(data[0],publicKey);
                    System.out.println("Received " + data[0] + " public key");
                } catch(Exception e) {}
                if(this.blockVerifier.publicKeys.size() == 3) {
                    this.readFileAndMulticast("BlockInput" + this.pid + ".txt");
                    this.ready = true;
                }
            }
        }
    }  

    public void multicast(String payload) {
        /* Multicast payload to the hard coded port numbers and ip address. */
        byte[] data = payload.getBytes();
        InetAddress theirIpAddress = null;
        try {
            theirIpAddress = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {}
        int[] theirPortNumbers = {4710, 4711, 4712};
        for (int theirPortNumber: theirPortNumbers) {
            DatagramPacket packet = new DatagramPacket(data, data.length, 
                                            theirIpAddress, theirPortNumber);
            try {
                this.socket.send(packet);
            } catch (IOException e) {}
        }
    }

    public int readFileAndMulticast(String filename) {
        /* The creation of a block was copied from the BlockInputE.java file. 
        First, we create a new buffered reader for the file that we want to 
        ingest. We create a context for the marshaller by providing a compatable 
        class and then create the marshaller that will be responsible for converting 
        our object to xml. For each line of the file that we read in, I emit the 
        block to the network.
        */
        int total = 0;
        try {
            BufferedReader br = new BufferedReader(new FileReader(filename));
            JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            String line;
            while ((line = br.readLine()) != null) {
                BlockRecord b = new BlockRecord();
                /* Generate a uuid as a block id then sign it with the process private key. */
                String suuid = new String(UUID.randomUUID().toString());
                b.setABlockID(suuid);
                String signedBlockID = Base64.getEncoder().encodeToString(this.signData(suuid.getBytes()));
                b.setASignedBlockID(signedBlockID);
                /* Set creating process as current process id */
                b.setACreatingProcess("Process" + this.pid);
                /* Set a timestamp for the block creation. Use pid for tie breakers. */
                Date date = new Date();
                String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
                b.setACreatedAt(T1 + "." + this.pid);
                /* Set data provided a file. */
                String[] tokens = line.split(" +");
                b.setFFname(tokens[0]);
                b.setFLname(tokens[1]);
                b.setFDOB(tokens[2]);
                b.setFSSNum(tokens[3]);
                b.setGDiag(tokens[4]);
                b.setGTreat(tokens[5]);
                b.setGRx(tokens[6]);
                /* Convert the object to xml and generate a SHA256 string that represents 
                that string of text. 
                Items in hash:
                    - BlockID
                    - SignedBlockID
                    - Creating Process
                    - Creation time
                    - First Name
                    - Last Name
                    - Date of Birth
                    - SSN
                    - Diagnosis
                    - Tratment
                    - Medecine
                */
                StringWriter sw1 = new StringWriter();
                jaxbMarshaller.marshal(b, sw1);
                String semiFullBlock = sw1.toString();
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(semiFullBlock.getBytes());
                byte[] byteData = md.digest();
                StringBuffer sb = new StringBuffer();
                for (int i = 0; i < byteData.length; i++) {
                    sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
                }
                String SHA256String = sb.toString();
                /* Using the SHA256 string, sign the string with this process private key. */
                byte[] digitalSignature = this.signData(SHA256String.getBytes());
                String SignedSHA256 = Base64.getEncoder().encodeToString(digitalSignature);
                /* Set the datahash and the signed datahash into the block. This will be used for auditing. */
                b.setADataHash(SHA256String);
                b.setASignedDataHash(SignedSHA256);
                /* After adding the SHA256 string and the signed string to the block. Convert
                it to an xml block again and multicast it out as an unverified block. */
                StringWriter sw2 = new StringWriter();
                jaxbMarshaller.marshal(b, sw2);
                String fullBlock = sw2.toString();
                this.multicastUnverifiedBlock(fullBlock);
                total++;
            }
        } catch (Exception e) {}
        return total;
    }

    public byte[] signData(byte[] data) {
        /* Given a byte array of data, use the private key of this process and
        sign the data such that only the public key can decode it to get the
        original data. */
        try {
            Signature signer = Signature.getInstance("SHA1withRSA");
            signer.initSign(this.keyPair.getPrivate());
            signer.update(data);
            return (signer.sign());
        } catch (Exception e) {
            return null;
        }
    }

    public void multicastUnverifiedBlock(String xml) {
        /* Given a string of xml, multicast it as an unverified block across the 
        network. We multicast by simply hard coding the port numbers of all the 
        clients that may be connected to the network and sending them a datagram.
        */
        byte[] data = xml.getBytes();
        InetAddress theirIpAddress = null;
        try {
            theirIpAddress = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {}
        int[] theirPortNumbers = {4710, 4711, 4712};
        for (int theirPortNumber: theirPortNumbers) {
            DatagramPacket packet = new DatagramPacket(data, data.length, 
                                            theirIpAddress, theirPortNumber);
            try {
                this.socket.send(packet);
            } catch (IOException e) {}
        }
    }
}


public class Blockchain {

    public static void main(String args[]) throws Exception {
        /* The main function that runs upon start up. We get a process id from the 
        command line and form that we calculate a port number to host the servers at.
        We start the server in charge of listening for unverified blocks 
        (unverifiedBlockServer) as well as a server in charge of listening for new
        block chains that have been multicasted. Afterwards, we provide the user with 
        options.
        */
        int pid;
        if (args.length < 1) pid = 0;
        else if (args[0].equals("0")) pid = 0;
        else if (args[0].equals("1")) pid = 1;
        else if (args[0].equals("2")) pid = 2;
        else pid = 0;

        int unverifiedBlockPort = 4710 + pid;
        int blockChainPort = 4810 + pid;

        System.out.println("Waiting for all processes to emit public keys.");

        UnverifiedBlockServer unverifiedBlockServer = new UnverifiedBlockServer(unverifiedBlockPort, pid);
        BlockChainServer blockChainServer = new BlockChainServer(blockChainPort, unverifiedBlockServer, pid);
        Thread blockChainThread = new Thread(blockChainServer);  
        Thread unverifiedBlockThread = new Thread(unverifiedBlockServer);
        blockChainThread.start(); 
        unverifiedBlockThread.start(); 

        while (true) {
            if (unverifiedBlockServer.ready)
                break;
            System.out.flush();
        }

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String i;
        System.out.println("Available Options:");
        System.out.println("\"R <filename>\": Read in a specified filename");
        System.out.println("\"V <hash,signature,threshold>\": Verify the blockchain. ");
        System.out.println("\"L\": List the current blockchain");
        System.out.println("Select an option. Available options <'R','V','L'>: ");

        do {
            i = in.readLine();
            if (i.contains("R ")) {
                String filename = i.split("[ ]")[1];
                int total = unverifiedBlockServer.readFileAndMulticast(filename);
                System.out.println(total + " records have been added to unverified blocks.");
            } else if (i.equals("V")) {
                blockChainServer.verifyBlockChain(0);
            } else if (i.equals("V hash")) {
                blockChainServer.verifyBlockChain(1);
            } else if (i.equals("V signature")) {
                blockChainServer.verifyBlockChain(2);
            } else if (i.equals("V threshold")) {
                blockChainServer.verifyBlockChain(3);
            } else if (i.equals("L")) {
                blockChainServer.listBlockChain();
            } else {
                System.out.println("Sorry. '" + i + "' is an invalid option.");
            }
        } while (true);
    }
}
