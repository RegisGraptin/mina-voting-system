import { Field, MerkleMap, MerkleMapWitness, method, Poseidon, PublicKey, Signature, SmartContract, State, state } from "o1js";

export class PrivateVoting extends SmartContract {

  // Smart contract owner
  @state(PublicKey) owner = State<PublicKey>();

  // Total votes
  @state(Field) totalVotes = State<Field>();

  // Merkle root of whitelisted voters
  @state(Field) votersRoot = State<Field>(); 

  // Merkle root of who has voted
  @state(Field) hasVotedRoot = State<Field>(); 

  init() {
    super.init();
    this.totalVotes.set(Field(0));
    this.votersRoot.set(new MerkleMap().getRoot());
    this.hasVotedRoot.set(new MerkleMap().getRoot());
    this.owner.set(this.sender.getAndRequireSignature()); 
  }

  @method async addVoter(
    voterAddress: PublicKey, 
    witness: MerkleMapWitness, 
    ownerSignature: Signature
  ) {
    // Verify the caller is the owner
    ownerSignature.verify(
      this.owner.getAndRequireEquals(), 
      [voterAddress.toFields()[0]]
    ).assertTrue();

    // Verify the voter isn't already whitelisted
    const [rootBefore, key] = witness.computeRootAndKey(Field(0));
    rootBefore.assertEquals(this.votersRoot.getAndRequireEquals());

    // Verify the key matches the voter's address
    const expectedKey = Poseidon.hash(voterAddress.toFields());
    key.assertEquals(expectedKey);

    // Update the key value and get the new root of the tree
    const [newRoot] = witness.computeRootAndKey(Field(1));
    this.votersRoot.set(newRoot);
  }


  @method async vote(
    vote: Field,
    voterPublicKey: PublicKey,
    whitelistWitness: MerkleMapWitness,
    hasVotedWitness: MerkleMapWitness,
    voterSignature: Signature
  ) {
    // Verify the voter signed this vote
    voterSignature.verify(voterPublicKey, [vote]).assertTrue();

    // Verify vote is valid (0 or 1)
    vote.assertLessThanOrEqual(Field(1));
    vote.assertGreaterThanOrEqual(Field(0));

    // Verify voter is whitelisted
    const [rootWhitelist, keyWhitelist] = whitelistWitness.computeRootAndKey(Field(1));
    rootWhitelist.assertEquals(this.votersRoot.getAndRequireEquals());
    keyWhitelist.assertEquals(Poseidon.hash(voterPublicKey.toFields()));

    // Verify voter hasn't voted before
    const [rootVoted, keyVoted] = hasVotedWitness.computeRootAndKey(Field(0));
    rootVoted.assertEquals(this.hasVotedRoot.getAndRequireEquals());
    keyVoted.assertEquals(Poseidon.hash(voterPublicKey.toFields()));

    // Mark voter as having voted
    const [newHasVotedRoot] = hasVotedWitness.computeRootAndKey(Field(1));
    this.hasVotedRoot.set(newHasVotedRoot);

    // Update total votes
    const currentTotalVotes = this.totalVotes.getAndRequireEquals();
    this.totalVotes.set(currentTotalVotes.add(vote));    
  }
}
