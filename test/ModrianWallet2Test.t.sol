// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2} from "lib/forge-std/src/Test.sol";
import {MondrianWallet2} from "src/MondrianWallet2.sol";

// Era Imports
import {
    Transaction,
    MemoryTransactionHelper
} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";
import {BOOTLOADER_FORMAL_ADDRESS} from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import {ACCOUNT_VALIDATION_SUCCESS_MAGIC} from
    "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";

// OZ Imports
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

// Foundry Devops
import {ZkSyncChainChecker} from "lib/foundry-devops/src/ZkSyncChainChecker.sol";

import "./SimpleReceiver.sol";

interface _CheatCodes {
    function ffi(string[] calldata) external returns (bytes memory);
}

contract MondrianWallet2Test is Test, ZkSyncChainChecker {
    using MessageHashUtils for bytes32;

    MondrianWallet2 implementation;
    MondrianWallet2 mondrianWallet;
    ERC20Mock usdc;
    SimpleReceiver receiver;
    bytes4 constant EIP1271_SUCCESS_RETURN_VALUE = 0x1626ba7e;
    _CheatCodes cheatCodes = _CheatCodes(VM_ADDRESS);

    uint256 constant AMOUNT = 1e18;
    bytes32 constant EMPTY_BYTES32 = bytes32(0);
    address constant ANVIL_DEFAULT_ACCOUNT = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

    ERC1967Proxy proxy;

    uint256 customGasPrice = 20 gwei;

    function setUp() public {
        implementation = new MondrianWallet2();
        proxy = new ERC1967Proxy(address(implementation), "");
        // e This line casts the proxy contract's address to the MondrianWallet2 type. This allows you to interact with the proxy as if it were an instance of MondrianWallet2. Essentially, when you call functions on mondrianWallet, the calls are forwarded by the proxy to the implementation contract.
        mondrianWallet = MondrianWallet2(address(proxy));
        mondrianWallet.initialize();
        mondrianWallet.transferOwnership(ANVIL_DEFAULT_ACCOUNT);
        usdc = new ERC20Mock();
        vm.deal(address(mondrianWallet), AMOUNT); // proxy gets ETH with a cheatcode
        receiver = new SimpleReceiver();
    }

    function testZkOwnerCanExecuteCommands() public {
        // Arrange
        address dest = address(usdc);
        uint256 value = 0; // @note if value was !=0, we would get executionFailed error message since ERC20Mock cannot receive ether
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, address(mondrianWallet), AMOUNT);

        Transaction memory transaction =
            _createUnsignedTransaction(mondrianWallet.owner(), 113, dest, value, functionData);

        // Act
        vm.prank(mondrianWallet.owner());
        mondrianWallet.executeTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);

        // Assert
        assertEq(usdc.balanceOf(address(mondrianWallet)), AMOUNT);
    }

    // You'll also need --system-mode=true to run this test
    function testZkValidateTransaction() public onlyZkSync {
        // Arrange
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, address(mondrianWallet), AMOUNT);
        Transaction memory transaction =
            _createUnsignedTransaction(mondrianWallet.owner(), 113, dest, value, functionData);
        transaction = _signTransaction(transaction);

        // Act
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        bytes4 magic = mondrianWallet.validateTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);

        // Assert
        assertEq(magic, ACCOUNT_VALIDATION_SUCCESS_MAGIC);
    }

    // @audit bug
    // @note needs a modified helper, see below
    function testZkExecuteTransactionSignedByAnyone() public {
        // Arrange
        address anyUser = makeAddr("anyUser");
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, anyUser, AMOUNT);

        Transaction memory transaction =
            _createUnsignedTransaction(mondrianWallet.owner(), 113, dest, value, functionData);

        // Act
        vm.startPrank(anyUser);
        transaction = _signTransaction(transaction); // if trx is not signed at all, next line would revert with [FAIL. Reason: ECDSAInvalidSignatureLength(0)]
        mondrianWallet.executeTransactionFromOutside(transaction);
        vm.stopPrank();

        // Assert
        assertEq(usdc.balanceOf(anyUser), AMOUNT);
    }

    function _signTransactionWithDummyKey(Transaction memory transaction) internal view returns (Transaction memory) {
        bytes32 unsignedTransactionHash = MemoryTransactionHelper.encodeHash(transaction);
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 DUMMY_PRIVATE_KEY = 0x0;
        //uint256 ANVIL_DEFAULT_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        (v, r, s) = vm.sign(DUMMY_PRIVATE_KEY, unsignedTransactionHash);
        Transaction memory signedTransaction = transaction;
        signedTransaction.signature = abi.encodePacked(r, s, v);
        return signedTransaction;
    }

    // @audit bug
    /**
     * 1. foundryup-zksync
     * 2. add is-system = true to foundry.toml so we can call system contracts
     * 3. forge build --zksync
     * 4. forge test --mt testZkAnyoneCanUpgrade --zksync
     */
    event Upgraded(address indexed implementation);

    function testZkAnyoneCanUpgrade() public onlyZkSync {
        address notOwner = makeAddr("notOwner");
        // address implementationAddress;
        // make `proxy˙ a state var to use this
        /*address proxyAddress = address(proxy);
        console2.log(proxyAddress);

        implementationAddress = _getImplementationAddress(proxyAddress);
        assertEq(implementationAddress, address(implementation));*/

        // newImplementation has to be a comtract and need to implement _authorizeUpgrade(address newImplementation)
        MondrianWallet2 newImplementation = new MondrianWallet2();

        // Expect the Upgraded event
        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(newImplementation)); // defining the expected event emission

        vm.prank(notOwner);
        mondrianWallet.upgradeToAndCall(address(newImplementation), "");

        /* implementationAddress = _getImplementationAddress(proxyAddress);
        assertEq(implementationAddress, address(0));*/
    }

    // @note this does not work for some reason...
    function _getImplementationAddress(address _proxyAddress) internal view returns (address implementationAddress) {
        // the EIP-1967 standard specifies that the implementation address of a proxy should be stored at a specific storage slot:
        bytes32 _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        //bytes32 _IMPLEMENTATION_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        bytes32 result;

        assembly {
            let ptr := mload(0x40) // Load the free memory pointer
            mstore(ptr, _IMPLEMENTATION_SLOT) // Store the implementation slot key in memory

            // Perform the staticcall
            let success :=
                staticcall(
                    100000000000, // Forward all available gas
                    _proxyAddress, // Address of the proxy contract
                    ptr, // Input location (start of our data in memory)
                    0x20, // Input size (32 bytes for the slot key)
                    0, // Output location (null for now)
                    0 // Output size (null for now)
                )

            // Check if the staticcall was successful
            if iszero(success) {
                let returndata_size := returndatasize()
                returndatacopy(ptr, 0, returndata_size)
                revert(ptr, returndata_size)
            }

            // Allocate memory for the result
            let returndata_size := returndatasize()
            mstore(0x40, add(ptr, returndata_size)) // Update the free memory pointer
            returndatacopy(ptr, 0, returndata_size) // Copy returndata to allocated memory

            result := mload(ptr) // Load the implementation address from memory
        }

        return address(uint160(uint256(result)));
    }

    // @audit ok
    function testZkCanSendValue() public {
        vm.txGasPrice(100);

        // Arrange
        address dest = address(receiver);
        uint256 value = 1;
        bytes memory functionData = ""; // No data needed for the receive function

        Transaction memory transaction =
            _createUnsignedTransaction(mondrianWallet.owner(), 113, dest, value, functionData);

        // Act
        vm.prank(mondrianWallet.owner());
        mondrianWallet.executeTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);

        // Assert
    }

    function testZkAnyoneCanCallPayForTransaction() public {
        // Arrange
        address anyUser = makeAddr("anyUser");
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(ERC20Mock.mint.selector, anyUser, AMOUNT);

        Transaction memory transaction =
            _createUnsignedTransaction(mondrianWallet.owner(), 113, dest, value, functionData);

        uint256 initialBalance = address(mondrianWallet).balance;

        vm.txGasPrice(100); //@note setting gas price to 100 gwei

        vm.startPrank(anyUser);
        mondrianWallet.payForTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);
        mondrianWallet.payForTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);
        mondrianWallet.payForTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);
        mondrianWallet.payForTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);
        mondrianWallet.payForTransaction(EMPTY_BYTES32, EMPTY_BYTES32, transaction);
        vm.stopPrank();

        uint256 endingBalance = address(mondrianWallet).balance;

        assert(endingBalance < initialBalance);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/
    function _signTransaction(Transaction memory transaction) internal view returns (Transaction memory) {
        bytes32 unsignedTransactionHash = MemoryTransactionHelper.encodeHash(transaction);
        // bytes32 digest = unsignedTransactionHash.toEthSignedMessageHash();
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 ANVIL_DEFAULT_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        (v, r, s) = vm.sign(ANVIL_DEFAULT_KEY, unsignedTransactionHash);
        Transaction memory signedTransaction = transaction;
        signedTransaction.signature = abi.encodePacked(r, s, v);
        return signedTransaction;
    }

    function _createUnsignedTransaction(
        address from,
        uint8 transactionType,
        address to,
        uint256 value,
        bytes memory data
    ) internal view returns (Transaction memory) {
        uint256 nonce = vm.getNonce(address(mondrianWallet));
        bytes32[] memory factoryDeps = new bytes32[](0);
        return Transaction({
            txType: transactionType, // type 113 (0x71).
            from: uint256(uint160(from)),
            to: uint256(uint160(to)),
            gasLimit: 16777216,
            gasPerPubdataByteLimit: 16777216,
            maxFeePerGas: 16777216,
            maxPriorityFeePerGas: 16777216,
            paymaster: 0,
            nonce: nonce,
            value: value,
            reserved: [uint256(0), uint256(0), uint256(0), uint256(0)],
            data: data,
            signature: hex"",
            factoryDeps: factoryDeps,
            paymasterInput: hex"",
            reservedDynamic: hex""
        });
    }

    /*  function testPwned() public {
        string[] memory cmds = new string[](2);
        cmds[0] = "touch";
        cmds[1] = string.concat("youve-been-pwned");
        cheatCodes.ffi(cmds);
    } */
}
