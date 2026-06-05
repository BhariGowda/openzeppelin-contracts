// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {TrieProof} from "@openzeppelin/contracts/utils/cryptography/TrieProof.sol";

/**
 * @title TrieProofInlinePoC
 * @dev Security PoC for the inline extension/branch node handling added in OZ #6351.
 *
 * We hand-build a Merkle-Patricia trie whose intermediate nodes are *inlined*
 * (RLP encoding < 32 bytes, so they are embedded inside their parent instead of
 * referenced by hash), then attempt a battery of forgeries against it.
 *
 *   Trie (root = keccak256(extension)):
 *
 *     Extension(path nibble [0])                         encoded: d7 10 <branch>
 *       --inlined--> Branch                              encoded: d5 <leaf0><leaf1> 80*15
 *           child[0] --inlined--> Leaf(path [], 0x01)    encoded: c2 20 01
 *           child[1] --inlined--> Leaf(path [], 0x02)    encoded: c2 20 02
 *
 *   key 0x00 (nibbles [0,0]) -> value 0x01
 *   key 0x01 (nibbles [0,1]) -> value 0x02
 *
 *   The single proof element [extension] inlines BOTH the branch and the leaf:
 *   exactly the case enabled by #6351.
 */
contract TrieProofInlinePoC is Test {
    bytes internal leaf0 = hex"c22001"; // RLP([0x20, 0x01]) -> Leaf, even path '', value 0x01
    bytes internal leaf1 = hex"c22002"; // RLP([0x20, 0x02]) -> Leaf, even path '', value 0x02

    bytes internal branchEnc; // d5 <leaf0><leaf1> 80*15
    bytes internal extension; // d7 10 <branch>
    bytes32 internal root;

    bytes internal constant KEY0 = hex"00"; // -> 0x01
    bytes internal constant KEY1 = hex"01"; // -> 0x02
    bytes internal constant VAL0 = hex"01";
    bytes internal constant VAL1 = hex"02";

    function setUp() public {
        // 16 children + 1 value. children[0]=leaf0, children[1]=leaf1, the other 14
        // children and the value slot are empty strings (0x80). 15 * 0x80:
        bytes memory empties = hex"808080808080808080808080808080";
        bytes memory branchPayload = bytes.concat(leaf0, leaf1, empties); // 3+3+15 = 21 bytes
        branchEnc = bytes.concat(hex"d5", branchPayload); // 0xc0+21 = 0xd5 ; total 22 bytes (< 32 => inlineable)

        bytes memory extPayload = bytes.concat(hex"10", branchEnc); // compact path 0x10 ([odd][0]) + inline branch
        extension = bytes.concat(hex"d7", extPayload); // 0xc0+23 = 0xd7 ; total 24 bytes

        root = keccak256(extension);

        // sanity on the hand-rolled lengths
        assertEq(branchEnc.length, 22);
        assertEq(extension.length, 24);
    }

    function _proof1(bytes memory a) internal pure returns (bytes[] memory p) {
        p = new bytes[](1);
        p[0] = a;
    }

    function _proof2(bytes memory a, bytes memory b) internal pure returns (bytes[] memory p) {
        p = new bytes[](2);
        p[0] = a;
        p[1] = b;
    }

    function _proof3(bytes memory a, bytes memory b, bytes memory c) internal pure returns (bytes[] memory p) {
        p = new bytes[](3);
        p[0] = a;
        p[1] = b;
        p[2] = c;
    }

    // -------------------------------------------------------------------------
    // 1. SANITY: the legitimate inline proofs verify (proves traversal really runs)
    // -------------------------------------------------------------------------

    function test_Legit_FullyInlined() public view {
        // single element inlines extension + branch + leaf
        assertTrue(TrieProof.verify(VAL0, root, KEY0, _proof1(extension)));
        assertTrue(TrieProof.verify(VAL1, root, KEY1, _proof1(extension)));
    }

    function test_Legit_OptionalElementsExpanded() public view {
        // the inlined nodes may *optionally* also be supplied as separate elements (#6379)
        assertTrue(TrieProof.verify(VAL0, root, KEY0, _proof2(extension, branchEnc)));
        assertTrue(TrieProof.verify(VAL0, root, KEY0, _proof3(extension, branchEnc, leaf0)));
        assertTrue(TrieProof.verify(VAL0, root, KEY0, _proof2(extension, leaf0))); // branch skipped, leaf provided
    }

    // -------------------------------------------------------------------------
    // 2. FORGERY ATTEMPTS — each must FAIL (return false / revert), never bypass
    // -------------------------------------------------------------------------

    /// @dev Claim key 0x00 maps to the OTHER committed value 0x02.
    function test_Forge_WrongValueForKey() public view {
        assertFalse(TrieProof.verify(VAL1, root, KEY0, _proof1(extension)));
        assertFalse(TrieProof.verify(VAL0, root, KEY1, _proof1(extension)));

        // the traversal genuinely returns the *committed* value, so the lie is caught by verify()
        (bytes memory got, TrieProof.ProofError err) = TrieProof.tryTraverse(root, KEY0, _proof1(extension));
        assertEq(err == TrieProof.ProofError.NO_ERROR, true);
        assertEq(got, VAL0); // not VAL1
    }

    /// @dev Tamper a committed value inside the inline leaf. Changing any byte changes the
    ///      root hash, so it cannot be presented against the original root.
    function test_Forge_TamperInlineLeafBreaksRoot() public view {
        bytes memory leaf0Evil = hex"c22009"; // value 0x09 (< 0x80 so it is valid single-byte RLP)
        bytes memory empties = hex"808080808080808080808080808080";
        bytes memory branchEvil = bytes.concat(hex"d5", leaf0Evil, leaf1, empties);
        bytes memory extEvil = bytes.concat(hex"d7", hex"10", branchEvil);

        // Against the REAL root: root mismatch -> rejected.
        (, TrieProof.ProofError err) = TrieProof.tryTraverse(root, KEY0, _proof1(extEvil));
        assertEq(err == TrieProof.ProofError.INVALID_ROOT, true);
        assertFalse(TrieProof.verify(hex"09", root, KEY0, _proof1(extEvil)));

        // Against ITS OWN root it is of course a valid (different) trie - confirms the only
        // thing stopping the forgery is the hash commitment, exactly as intended.
        assertTrue(TrieProof.verify(hex"09", keccak256(extEvil), KEY0, _proof1(extEvil)));
    }

    /// @dev Proof-length manipulation: append a trailing junk element after a fully-inlined proof.
    ///      The value is reached inline at i=0 which must be the LAST element.
    function test_Forge_TrailingPadding() public view {
        (, TrieProof.ProofError err) = TrieProof.tryTraverse(root, KEY0, _proof2(extension, extension));
        assertEq(err == TrieProof.ProofError.INVALID_EXTRA_PROOF_ELEMENT, true);
        assertFalse(TrieProof.verify(VAL0, root, KEY0, _proof2(extension, extension)));
    }

    /// @dev Optional-element substitution: when proving KEY0, supply the *wrong* leaf (leaf1)
    ///      as the optional follow-up element. _match must reject it (byte inequality) and the
    ///      now-superfluous element trips the extra-element guard.
    function test_Forge_WrongOptionalLeaf() public view {
        (, TrieProof.ProofError err) = TrieProof.tryTraverse(root, KEY0, _proof2(extension, leaf1));
        assertEq(err == TrieProof.ProofError.INVALID_EXTRA_PROOF_ELEMENT, true);
        assertFalse(TrieProof.verify(VAL0, root, KEY0, _proof2(extension, leaf1)));
    }

    /// @dev Try to smuggle leaf1's value through KEY0 by presenting a branch whose child[0]
    ///      has been swapped to leaf1. Swapping bytes changes the root -> INVALID_ROOT.
    function test_Forge_SwapBranchChildBreaksRoot() public view {
        bytes memory empties = hex"808080808080808080808080808080";
        bytes memory branchSwapped = bytes.concat(hex"d5", leaf1, leaf1, empties); // child[0] := leaf1
        bytes memory extSwapped = bytes.concat(hex"d7", hex"10", branchSwapped);

        (, TrieProof.ProofError err) = TrieProof.tryTraverse(root, KEY0, _proof1(extSwapped));
        assertEq(err == TrieProof.ProofError.INVALID_ROOT, true);
        assertFalse(TrieProof.verify(VAL1, root, KEY0, _proof1(extSwapped)));
    }

    /// @dev Non-existent key. Walking into an empty branch slot (0x80) must not yield a value.
    ///      The verifier safely *reverts* (RLP decode of the 0x80 child as a list fails) rather
    ///      than ever returning a value — a rejection, not a bypass.
    function test_Forge_NonexistentKey() public {
        // key 0x02 -> nibbles [0,2]; branch child[2] is empty (0x80).
        bytes memory key2 = hex"02";
        vm.expectRevert(); // RLP decode of the empty (0x80) child as a list reverts
        this.callTraverse(root, key2, _proof1(extension));

        vm.expectRevert();
        this.callVerify(VAL0, root, key2, _proof1(extension));
    }

    function callTraverse(bytes32 r, bytes memory k, bytes[] memory p) external pure returns (bytes memory) {
        return TrieProof.traverse(r, k, p);
    }

    function callVerify(
        bytes memory v,
        bytes32 r,
        bytes memory k,
        bytes[] memory p
    ) external pure returns (bool) {
        return TrieProof.verify(v, r, k, p);
    }
}
