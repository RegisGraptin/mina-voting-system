import { AccountUpdate, Field, MerkleMap, Mina, Poseidon, PrivateKey, PublicKey, Signature } from 'o1js';
import { PrivateVoting } from './PrivateVoting';

/*
 * This file specifies how to test the `Add` example smart contract. It is safe to delete this file and replace
 * with your own tests.
 *
 * See https://docs.minaprotocol.com/zkapps for more info.
 */

let proofsEnabled = false;

describe('PrivateVoting', () => {
  let deployerAccount: Mina.TestPublicKey,
    deployerKey: PrivateKey,
    senderAccount: Mina.TestPublicKey,
    senderKey: PrivateKey,
    user1: Mina.TestPublicKey,
    user2: Mina.TestPublicKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: PrivateVoting;

  beforeAll(async () => {
    if (proofsEnabled) await PrivateVoting.compile();
  });

  beforeEach(async () => {
    const Local = await Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    [deployerAccount, senderAccount, user1, user2] = Local.testAccounts;
    deployerKey = deployerAccount.key;
    senderKey = senderAccount.key;

    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new PrivateVoting(zkAppAddress);
  });

  async function localDeploy() {
    const txn = await Mina.transaction(deployerAccount, async () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      await zkApp.deploy();
    });
    await txn.prove();
    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('generates and deploys the `PrivateVoting` smart contract', async () => {
    await localDeploy();
    const totalVotes = zkApp.totalVotes.get();
    expect(totalVotes).toEqual(Field(0));
  });

  it('correctly whitelist a new user and cast a vote', async () => {
    await localDeploy();
  
    const whitelistMerkleMap = new MerkleMap();
  
    const whitelistWitness = whitelistMerkleMap.getWitness(Poseidon.hash(user1.toFields()));
    const signature = Signature.create(deployerKey, [user1.toFields()[0]]);

    const txn = await Mina.transaction(senderAccount, async () => {
      await zkApp.addVoter(user1, whitelistWitness, signature);
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    whitelistMerkleMap.set(Poseidon.hash(user1.toFields()), Field(1));

    // Correctly set a vote
    const voteMerkleMap = new MerkleMap();
    const voteWitness = voteMerkleMap.getWitness(Poseidon.hash(user1.toFields()));
    
    const vote = Field(1);

    const voteTxn = await Mina.transaction(senderAccount, async () => {
      await zkApp.vote(
        vote, 
        user1, 
        whitelistMerkleMap.getWitness(Poseidon.hash(user1.toFields())), 
        voteWitness, 
        Signature.create(user1.key, [vote])
      );
    });
    await voteTxn.prove();
    await voteTxn.sign([senderKey]).send();

    // Check that the total votes have been updated correctly
    const totalVotes = zkApp.totalVotes.get();
    expect(totalVotes).toEqual(Field(1));

  });

});
