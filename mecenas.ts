import { BITBOX } from "bitbox-sdk";
import { P2PKH, SigHash, signWith, Spedn, TxBuilder } from "spedn";

const bitbox = new BITBOX();
const mnemonic = "draw parade crater busy book swim soldier tragic exit feel top civil";
const wallet = bitbox.HDNode.fromSeed(bitbox.Mnemonic.toSeed(mnemonic));
const bob = bitbox.HDNode.derivePath(wallet, "m/44'/145'/1'/0/0");
const mecenas = bitbox.Address.cashToHash160("qztk55juvcuxjj5v9cdsrxxysv4wfuhu4vmxld6v6r");
const protege = bitbox.Address.cashToHash160("qztk55juvcuxjj5v9cdsrxxysv4wfuhu4vmxld6v6r");



async function main() {
  const compiler = new Spedn();
  const Mecenas = await compiler.compileCode(`
  contract Mecenas(Ripemd160 pkh, Ripemd160 pkh2, int pledge) {
    challenge protege(PubKey pk, Sig sig, bin ver, bin hPhSo, bin scriptCode, bin value, bin nSequence, bin hashOutput, bin tail ) {
        verify size(ver) == 4;
        verify size(hPhSo) == 100;
        verify size(value) == 8;
        verify size(nSequence) == 4;
        verify size(hashOutput) == 32;
        verify size(tail) == 8;

        //verify hash160(pk) == pkh;
        verify checkSig(sig, pk);
        bin preimage = ver . hPhSo . scriptCode . value . nSequence . hashOutput . tail;
        verify checkDataSig(toDataSig(sig), sha256(preimage), pk); 
        int fee = 1000;
        bin amount2 = num2bin(pledge, 8);
        bin amount1 =num2bin(bin2num(value)-pledge - fee, 8);

        bin opDup = 0x76;
        bin opEqual = 0x87;
        bin opHash160 = 0xa9;
        bin pushHash = 0x14;
        bin newVarInt1 = 0x17;
        bin newVarInt2 = 0x19;
        bin opEqualverify = 0x88;
        bin opChecksig = 0xac;

        bin [_, rawscr] = scriptCode @ 3;
        verify checkSequence(30d);
        verify bin2num(ver) >= 2;

        bin out1 = amount1  . newVarInt1 . opHash160 . pushHash . hash160(rawscr) . opEqual ;
        bin out2 = amount2  . newVarInt2 . opDup . opHash160 . pushHash . pkh . opEqualverify . opChecksig;
        verify hash256(out1 . out2) == Sha256(hashOutput); 
    } 

    challenge mecenas(PubKey pk, Sig sig) {
        verify hash160(pk) == pkh2;
        verify checkSig(sig, pk);
    }

}
  `);
  compiler.dispose();

  console.log(Mecenas);
  console.log(protege);
  console.log(mecenas);

  const mec = new Mecenas({
    pkh: Buffer.from(protege, "hex"),
    pkh2: Buffer.from(mecenas, "hex"),
    pledge: 10000
  });

  console.log(mec.getAddress("mainnet"));
  console.log(mec.challengeSpecs.protege);

  const coins = await mec.findCoins("mainnet");
  console.log(coins);



  let addr = new P2PKH(bob.getIdentifier());


  const txid = await new TxBuilder("mainnet")
     .from(coins, (input, context) =>
        input.receive({
           sig: context.sign(bob.keyPair, SigHash.SIGHASH_ALL),
           pubKey: bob.getPublicKeyBuffer()
        }), 
     )
     //.from(bobsCoins[14], signWith(bob.keyPair))
     .to(mec.getAddress("mainnet"),889000)
     .to("bitcoincash:qr7k0f9zvvjrv3q6g9ynzn8ygdrcsy3lt58gytla5c", 10000)
     //.to(alice.getAddress())
     //.withTimelock(567654)
     //.broadcast();

  console.log(txid);
}
main();
