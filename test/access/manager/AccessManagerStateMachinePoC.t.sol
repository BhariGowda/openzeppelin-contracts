// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {AccessManager} from "@openzeppelin/contracts/access/manager/AccessManager.sol";
import {IAccessManager} from "@openzeppelin/contracts/access/manager/IAccessManager.sol";

/// @notice State-machine attack PoCs for AccessManager. Each test encodes a claimed
/// attack from the hunt and asserts the contract's actual (safe) behavior.
contract AccessManagerStateMachinePoC is Test {
    AccessManager mgr;

    address rootAdmin = address(0xA11CE);
    address delayedAdmin = address(0xDEADBEEF);
    address attacker = address(0xBAD);

    uint32 constant DELAY = 10 days;
    uint64 constant LABEL_TARGET_ROLE = 42;
    uint64 ADMIN_ROLE;

    function setUp() public {
        mgr = new AccessManager(rootAdmin);
        ADMIN_ROLE = mgr.ADMIN_ROLE();
        // Give delayedAdmin ADMIN_ROLE but with a 10-day execution delay.
        vm.prank(rootAdmin);
        mgr.grantRole(ADMIN_ROLE, delayedAdmin, DELAY);
    }

    // An admin-restricted op whose only delay is the caller's execution delay.
    function _op() internal pure returns (bytes memory) {
        return abi.encodeCall(IAccessManager.labelRole, (LABEL_TARGET_ROLE, "x"));
    }

    function _schedule() internal returns (bytes32 id) {
        bytes memory data = _op();
        vm.prank(delayedAdmin);
        (id, ) = mgr.schedule(address(mgr), data, 0);
    }

    // ---- PATTERN A: schedule bypass ----------------------------------------

    /// Same-block schedule+execute must revert NotReady (delay not bypassable).
    function test_A_sameBlockExecuteReverts() public {
        bytes memory data = _op();
        bytes32 id = _schedule();
        // timepoint == now + DELAY, strictly in the future this block.
        assertEq(mgr.getSchedule(id), uint48(block.timestamp + DELAY));

        vm.prank(delayedAdmin);
        vm.expectRevert(abi.encodeWithSelector(IAccessManager.AccessManagerNotReady.selector, id));
        mgr.execute(address(mgr), data);
    }

    /// A caller WITH an execution delay cannot execute without scheduling first.
    function test_A_executeWithoutScheduleReverts() public {
        bytes memory data = _op();
        bytes32 id = mgr.hashOperation(delayedAdmin, address(mgr), data);

        vm.prank(delayedAdmin);
        vm.expectRevert(abi.encodeWithSelector(IAccessManager.AccessManagerNotScheduled.selector, id));
        mgr.execute(address(mgr), data);
    }

    /// An already-executed operation cannot be executed a second time.
    function test_A_doubleExecuteReverts() public {
        bytes memory data = _op();
        bytes32 id = _schedule();

        vm.warp(block.timestamp + DELAY);
        vm.prank(delayedAdmin);
        mgr.execute(address(mgr), data); // first execution succeeds

        vm.prank(delayedAdmin);
        vm.expectRevert(abi.encodeWithSelector(IAccessManager.AccessManagerNotScheduled.selector, id));
        mgr.execute(address(mgr), data); // replay fails
    }

    // ---- PATTERN B: role escalation ----------------------------------------

    /// A non-admin cannot grant itself ADMIN_ROLE.
    function test_B_attackerCannotSelfGrantAdmin() public {
        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessManager.AccessManagerUnauthorizedAccount.selector, attacker, ADMIN_ROLE)
        );
        mgr.grantRole(ADMIN_ROLE, attacker, 0);
    }

    /// grantRole's executionDelay argument does NOT bypass the role grant delay.
    function test_B_executionDelayZeroDoesNotBypassGrantDelay() public {
        uint64 role = 7;
        // root admin configures a 5-day grant delay for `role`.
        vm.prank(rootAdmin);
        mgr.setGrantDelay(role, 5 days);
        // minSetback (5 days) applies to the grant-delay change itself; warp past it.
        vm.warp(block.timestamp + 5 days);
        assertEq(mgr.getRoleGrantDelay(role), 5 days);

        // Grant with executionDelay = 0. Membership must still be deferred by the grant delay.
        vm.prank(rootAdmin);
        mgr.grantRole(role, attacker, 0);

        (bool isMember, ) = mgr.hasRole(role, attacker);
        assertFalse(isMember, "membership must not be active before grant delay elapses");

        vm.warp(block.timestamp + 5 days);
        (isMember, ) = mgr.hasRole(role, attacker);
        assertTrue(isMember, "membership active only after grant delay");
    }

    // ---- PATTERN C: time manipulation --------------------------------------

    /// Boundary check: NotReady at timepoint-1, success at exactly timepoint.
    function test_C_offByOneBoundary() public {
        bytes memory data = _op();
        bytes32 id = _schedule();
        uint256 tp = mgr.getSchedule(id);

        vm.warp(tp - 1);
        vm.prank(delayedAdmin);
        vm.expectRevert(abi.encodeWithSelector(IAccessManager.AccessManagerNotReady.selector, id));
        mgr.execute(address(mgr), data);

        vm.warp(tp); // exactly ready
        vm.prank(delayedAdmin);
        mgr.execute(address(mgr), data); // succeeds
    }

    /// schedule() cannot reset the timer on an already-pending operation.
    function test_C_cannotRescheduleWhilePending() public {
        bytes memory data = _op();
        bytes32 id = _schedule();

        vm.warp(block.timestamp + 5 days); // still pending (< DELAY)
        vm.prank(delayedAdmin);
        vm.expectRevert(abi.encodeWithSelector(IAccessManager.AccessManagerAlreadyScheduled.selector, id));
        mgr.schedule(address(mgr), data, 0);
    }

    // ---- PATTERN D: cancel/execute race ------------------------------------

    /// An operation cannot be executed after it is cancelled.
    function test_D_executeAfterCancelReverts() public {
        bytes memory data = _op();
        bytes32 id = _schedule();

        // delayedAdmin cancels its own scheduled op.
        vm.prank(delayedAdmin);
        mgr.cancel(delayedAdmin, address(mgr), data);

        vm.warp(block.timestamp + DELAY);
        vm.prank(delayedAdmin);
        vm.expectRevert(abi.encodeWithSelector(IAccessManager.AccessManagerNotScheduled.selector, id));
        mgr.execute(address(mgr), data);
    }

    /// An unrelated account (not proposer/admin/guardian) cannot cancel.
    function test_D_unauthorizedCancelReverts() public {
        bytes memory data = _op();
        _schedule();

        vm.prank(attacker);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessManager.AccessManagerUnauthorizedCancel.selector,
                attacker,
                delayedAdmin,
                address(mgr),
                bytes4(data)
            )
        );
        mgr.cancel(delayedAdmin, address(mgr), data);
    }

    // ---- PATTERN E: cross-function state corruption -------------------------

    /// Reducing a member's execution delay is itself setback-protected: the old
    /// (larger) delay keeps applying for `oldDelay - newDelay`, so an in-flight
    /// schedule cannot be made executable earlier by shrinking the delay.
    function test_E_delayReductionIsSetbackProtected() public {
        uint64 role = 9;
        // Configure a target function gated by `role`, grant attacker the role w/ 10d delay.
        vm.startPrank(rootAdmin);
        mgr.grantRole(role, attacker, DELAY);
        vm.stopPrank();

        (, uint32 cur, uint32 pend, uint48 effect) = mgr.getAccess(role, attacker);
        assertEq(cur, DELAY);

        // root reduces the delay to 1 day.
        vm.prank(rootAdmin);
        mgr.grantRole(role, attacker, 1 days);

        (, cur, pend, effect) = mgr.getAccess(role, attacker);
        // Current delay still the OLD value; new value pending with an effect in the future.
        assertEq(cur, DELAY, "old delay must still apply immediately after reduction");
        assertEq(pend, 1 days);
        assertEq(effect, uint48(block.timestamp + (DELAY - 1 days)), "reduction deferred by the shrink amount");
    }
}
