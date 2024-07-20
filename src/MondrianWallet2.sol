// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// @note difference between ethereum and zksync
// - IN ETH: to deploy a smart contract, you just send an ethereum trx with the compiled bytecode of the contract, without any recipient
// - IN ZKSYC: you need to send this to a special system contract (contractDeployer) which will then create the smart contract. Main differences between ethereum and zkysínc is the system contractS.
// This is why `forge create` will not work, use `forge create --zksync --legacy` instead

// @note some of the opcodes are not supported by the VM by default and they are implemented via “system contracts” — these contracts are located in a special kernel space, i.e. in the address space in range [0..2^16-1], and they have some special privileges, which users’ contracts don’t have. These contracts are pre-deployed at the genesis and updating their code can be done only via system upgrade, managed from L1.

// @note to work with zksync:
// 1. foundryup-zksync
// 2. foudnry build --zksync

/**
 * @note Lifecycle of a type 113 (0x71) trx (account abstraction trx) (trx type is a parameter in the Transaction struct)
 *
 * msg.sender is always the bootloader system contract, it is like a superadmin
 *
 * PHASE 1 - validation
 * 1. user sends the trx to the "zksync API client" (sort of a light node)
 * 2. the zksync API client checks if the nonce is unique by checking with the NonceHolder system contract
 * 3. The zkSync API client calls validateTransaction, which MUST update the nonce
 * 4. The zkSync API client checks if the nonce if actually updated in validateTransaction. If not, revert
 * 5. The zkSync API client calls payForTransaction, or prepareForPaymaster & validateAndPayForPaymasterTransaction
 * 6. The zkSync API client checks if the bootloader got payed
 *
 *
 * PHASE 2 - execution
 * 7. The zkSync API client passes the validated trx to the main node / sequencer node (as of today, they are the same)
 * 8. The main node calls executeTransaction
 * 9. if a PayMaster is used, the postTransaction is called
 *
 */

// zkSync Era Imports
import {
    IAccount, // e every single address on zkSync have the functions that are defined here
    ACCOUNT_VALIDATION_SUCCESS_MAGIC
} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import {
    Transaction, // @note Structure used to represent a zkSync transaction.
    MemoryTransactionHelper
} // @note there is a func totalRequiredBalance() that we will use to check how much gas is reqd to send trx
from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";
// @note so that we can call system contracts
import {SystemContractsCaller} from
    "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/SystemContractsCaller.sol";
import {
    NONCE_HOLDER_SYSTEM_CONTRACT, // @note another system contract. Has the nonce of every single smart contract on zksync
    // The bootloader is a key component of the system that manages the execution of layer 2 transactions. It is a specialized software that is not deployed like a regular contract, but rather runs within a node as part of the execution environment.
    // since the bootloader is part of the node software and not a deployed smart contract, it does not have the same presence on blockchain explorers as user-deployed contracts.
    BOOTLOADER_FORMAL_ADDRESS, // @note another system contract, it is alwasy the msg.sender for type 113 trxs
    DEPLOYER_SYSTEM_CONTRACT
} from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import {INonceHolder} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/INonceHolder.sol";
import {Utils} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/Utils.sol";

// OZ Imports
// e to have things in proper format
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {console} from "lib/forge-std/src/Test.sol";

/**
 * @title MondrianWallet2
 * @notice Its upgradable! So there shouldn't be any issues because we can just upgrade!... right?
 */

// @note in UUPS upgradeability pattern, upgradability is handled in the implementation and can eventually be removed
// Function related to upgradability is in UUPSUpgradeable
contract MondrianWallet2 is IAccount, Initializable, OwnableUpgradeable, UUPSUpgradeable {
    using MemoryTransactionHelper for Transaction; // @note so that we can use totalRequriedBalance() and encodeHash(), payToTheBootloader() on Transaction

    error MondrianWallet2__NotEnoughBalance();
    error MondrianWallet2__NotFromBootLoader();
    error MondrianWallet2__ExecutionFailed();
    error MondrianWallet2__NotFromBootLoaderOrOwner();
    error MondrianWallet2__FailedToPay();
    error MondrianWallet2__InvalidSignature();

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/
    modifier requireFromBootLoader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) {
            revert MondrianWallet2__NotFromBootLoader();
        }
        _;
    }

    modifier requireFromBootLoaderOrOwner() {
        // @note owner() defined in OwnableUpgradeable
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS && msg.sender != owner()) {
            revert MondrianWallet2__NotFromBootLoaderOrOwner();
        }
        _;
    }

    // @note initializer keyword ensures it can be called only once
    // @note the initializer function (e.g., initialize) is called via the proxy, which sets up _owner in the proxy’s storage.
    // @audit anyone can call this
    function initialize() public initializer {
        __Ownable_init(msg.sender); // e set onwer. But does this work? Will not the msg.sender be the ContractDeployer?
        __UUPSUpgradeable_init();
    }

    // @audit contract cannot receive funds. Missing:
    // receive () external payable {}

    // @note this is the implementation contract -> should not have any state vars
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /*//////////////////////////////////////////////////////////////
                           EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice must increase the nonce
     * @notice must validate the transaction (check the owner signed the transaction)
     * @notice also check to see if we have enough money in our account - e since we are not using a paymaster
     */
    // q is the nonce increased anywhere? YES
    // e in ethereum, it is called validateUserOp, but zksync does not care if we send an AA trx or a reular trx
    // e The magic value that should be equal to the signature of this function if the user agrees to proceed with the transaction.
    // e we completely ignore the first 2 params
    function validateTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction memory _transaction)
        external
        payable
        requireFromBootLoader
        returns (bytes4 magic)
    {
        return _validateTransaction(_transaction);
    }

    // @note has a modifier
    function executeTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction memory _transaction)
        external
        payable
        requireFromBootLoaderOrOwner
    {
        _executeTransaction(_transaction);
    }

    // e anyone can call this, but it is ok, they will just pay the gas
    // e to send as a regular trx: no AA stuff, no bootloader stuff...
    // anyone can call this, but they will pay the gas
    function executeTransactionFromOutside(Transaction memory _transaction) external payable {
        _validateTransaction(_transaction);
        // @audit return value not checked
        /**
         * Correction:
         * bytes4 magic =  _validateTransaction(_transaction);
         * if (magic != ACCOUNT_VALIDATION_SUCCESS_MAGIC) {
         *  revert MondrianWallet2__InvalidSignature();
         * }
         */
        _executeTransaction(_transaction);
    }

    // e Method for paying the bootloader for the transaction.
    // @audit anyone can call this, should be only bootloader
    function payForTransaction(bytes32, /*_txHash*/ bytes32, /*_suggestedSignedHash*/ Transaction memory _transaction)
        external
        payable
    {
        /* bool success = _transaction.payToTheBootloader(); // e defined in TransactionMemoryHelper
        if (!success) {
            revert MondrianWallet2__FailedToPay();
        }*/
    }

    /**
     * @dev We never call this function, since we are not using a paymaster
     */
    function prepareForPaymaster(
        bytes32, /*_txHash*/
        bytes32, /*_possibleSignedHash*/
        Transaction memory /*_transaction*/
    ) external payable {}

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    function _validateTransaction(Transaction memory _transaction) internal returns (bytes4 magic) {
        /**
         * @note To increase the nonce, we need to call the NonceHolder.
         * But is requires extra consideration to call system contracts, we need to do some special things.
         * - in foundry.toml, we need to add a flag to the remappings, after `]`: is-system = true
         * - as of the recording, we indtead need to add `--system-mode=true` to the command line when compiling
         */

        // @note this increases the nonce. THis is a systems contract simulation. Only works if foundry.toml has the proper flag, see above
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (_transaction.nonce))
        );

        // Check if the account has enough balance to pay the value and fee - if not, this would fail anyway, but much later
        // -> would be waste of fees
        // e this func is defined in MemoryTransactionHelper. We can call this like this since we are using MTH for Transaction vars
        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        if (totalRequiredBalance > address(this).balance) {
            revert MondrianWallet2__NotEnoughBalance();
        }

        // Check the signature
        bytes32 txHash = _transaction.encodeHash(); // e this is another func from MemoryTransactionHelper
        // @audit relies on ECDSA. Zksync accounts may have different signign methods. https://codehawks.cyfrin.io/c/2024-05-Mondrian-Wallet/results?t=report&lt=contest&sc=reward&sj=reward&page=1
        // @note https://docs.zksync.io/build/developer-reference/account-abstraction/building-smart-accounts
        /**
         *
         * @param the signing method is currently hardcoded to use ECDSA signatures, which rely on private keys. This is evident in the _validateTransaction function where the contract uses the ECDSA.recover method to validate the transaction signature.
         */

        //@note first param should be convertedHash, not txHash:
        // normally, to have things in proper format we have to use: convertedHash = MessageHashUtils.toEthSignedMessagehash(txHash);
        // but encodeHash() takes care of it above.
        address signer = ECDSA.recover(txHash, _transaction.signature);
        bool isValidSigner = signer == owner();
        if (isValidSigner) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }
        return magic;
    }

    function _executeTransaction(Transaction memory _transaction) internal {
        address to = address(uint160(_transaction.to));

        // we need to safecast as we may need to use value in a systemcall which takes uint128
        uint128 value = Utils.safeCastToU128(_transaction.value);
        bytes memory data = _transaction.data;

        // if "to" is a system contract (e.g. if we deploy a contract), we need to call the systemContractCaller
        // @audit other system contracts cannot be called https://docs.zksync.io/build/developer-reference/era-contracts/system-contracts

        /**
         * This was for testing if interaction with MsgValueSimulator is included, can we or not transfer value.
         * Could not make it work
         *  Check if Ether needs to be transferred
         *         if (value > 0) {
         *         // Use MsgValueSimulator for Ether transfers
         *         bytes memory callData = abi.encodeWithSignature("simulateCall(address,uint256,bytes)", to, value, data);
         *         SystemContractsCaller.systemCallWithPropagatedRevert(
         *             gas,
         *             address(0x0000000000000000000000000000000000000900), // Address of MsgValueSimulator
         *             0, // No value is sent to the MsgValueSimulator
         *             callData
         *         );
         *     } else {
         */
        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            // e if we deploy throuhg this
            uint32 gas = Utils.safeCastToU32(gasleft());
            SystemContractsCaller.systemCallWithPropagatedRevert(gas, to, value, data);
        } else {
            bool success;
            // @audit but call works differently in zkSync. Patrick uses assembly instead
            // This function handles the actual execution of the user-specified transaction, which includes transferring a specified amount to the target address (to).
            // This is not related to the gas fees but to the action the user intends to perform (e.g., transferring tokens, calling another contract, etc.).
            (success,) = to.call{value: value}(data);
            if (!success) {
                revert MondrianWallet2__ExecutionFailed();
            }
        }
    }

    // Needed for UUPS
    function _authorizeUpgrade(address newImplementation) internal override {
        /**
         * @audit anyone can perform the upgrade
         * From the UUPSUpgradebale contract:
         *  * The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.
         *
         *
         *
         * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
         * {upgradeToAndCall}.
         *
         * Normally, this function will use an xref:access.adoc[access control] modifier such as {Ownable-onlyOwner}.
         *
         * ```solidity
         * function _authorizeUpgrade(address) internal onlyOwner {}
         * ```
         */
    }
}
