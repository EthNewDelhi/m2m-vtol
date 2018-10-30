pragma solidity ^0.4.24;

import "./ownership/Ownable.sol";
import "./cryptography/ECDSA.sol";
// import "./interfaces/IERC20.sol";

/**
* @title Micro payments contract for m2m payments based on one-to-many state channel architecture
* @notice Only contract owner can add or remove trusted contract addresses
*/
contract M2MMicroPayments is Ownable{

	// number of blocks to wait after an uncooperative close is initiated
	uint256 public challengePeriod;

	// Future TO-DO - implement upgradeable proxy architecture
	// contract semantic version
	string public constant VERSION = '0.0.1';

	struct Channel{
		uint256 deposit;
		uint256 openBlockNumber;
	}

	struct ClosingRequest{
		uint256 closingBalance;
		uint256 settleBlockNumber;
	}

	// IERC20 public token;

	mapping (bytes32 => Channel) public channels;
	mapping (bytes32 => ClosingRequest) public closingRequests;

	mapping (address => bool) public trustedContracts;
	mapping (bytes32 => uint256) public withdrawnBalances;
	
	/**
     * @notice Modifier to make a function callable only if the sender is trusted
     */
	modifier isTrusted() {
		require (trustedContracts[msg.sender], 'address not trusted'); 
		_; 
	}

	//////////
    // Events
    //////////

    event ChannelCreated(
        address indexed sender,
        address indexed receiver,
        uint256 deposit);

    event ChannelToppedUp (
        address indexed sender,
        address indexed receiver,
        uint256 indexed openBlockNumber,
        uint256 deposit);

    event ChannelCloseRequested(
        address indexed sender,
        address indexed receiver,
        uint256 indexed openBlockNumber,
        uint256 balance);

    event ChannelSettled(
        address indexed sender,
        address indexed receiver,
        uint256 indexed openBlockNumber,
        uint256 balance,
        uint256 receiverTokens);

    event ChannelWithdraw(
        address indexed sender,
        address indexed receiver,
        uint256 indexed openBlockNumber,
        uint256 remainingBalance);

    event TrustedContract(
        address indexed trustedContract,
        bool trustedStatus);

    /////////////
    // Functions
    /////////////

    /**
     * @notice Constructor
     * @param _challengePeriod A fixed number of blocks representing the challenge period
     * @param _trustedContracts Array of contract addresses that can be trusted to open and top up channels on behalf of a sender
     */
    constructor (
        uint256 _challengePeriod,
        address[] _trustedContracts)
    public {
    	require(_challengePeriod >= 500, "challenge period must span atleast 500 blocks");
    	challengePeriod = _challengePeriod;
    	addTrustedContracts(_trustedContracts);
    }

    /*
     *  External functions
     */

    /**
     * @notice payable function which creates a channel between `msg.sender` and `_receiver` with a net amount of `msg.value` 
     * @param _receiver server side of transfer
     * @param _deposit amount of ETH escrowed by the client
     */
    function createChannel(address _receiver, uint256 _deposit) external payable{
    	require(msg.value == _deposit, 'invalid deposit');
    	createChannelPrivate(msg.sender, _receiver, _deposit);
    }

    /**
     * @notice Increase the channel deposit with `_addedDeposit`
     * @param _receiver Server side of transfer
     * @param _openBlockNumber Block number at which the channel was created
     * @param _addedDeposit TopUp amount
     */
    function topUp(
        address _receiver,
        uint256 _openBlockNumber,
        uint256 _addedDeposit)
    external payable {
    	require(msg.value == _addedDeposit, 'invalid topUp value');
    	updateInternalBalanceStructs(
            msg.sender,
            _receiver,
            _openBlockNumber,
            _addedDeposit
        );
    }

    /**
     * @notice Allows channel receiver to withdraw tokens
     * @param _openBlockNumber Block number at which the channel was created
     * @param _balance Partial or total amount of tokens owed by the sender to the receiver
     * @param _balanceMsgSig The balance message signed by the sender
     */
    function withdraw(
        uint256 _openBlockNumber,
        uint256 _balance,
        bytes _balanceMsgSig)
    external {
    	require(_balance > 0, "zero withdrawal amount");

    	// Derive sender address from signed balance proof
        address sender = extractBalanceProofSignature(
            msg.sender,
            _openBlockNumber,
            _balance,
            _balanceMsgSig
        );

        bytes32 key = getKey(sender, msg.sender, _openBlockNumber);

        require(channels[key].openBlockNumber > 0, 'channel does not exist');
        require (closingRequests[key].settleBlockNumber == 0, 'channel is in the challenge period');

        require (_balance <= channels[key].deposit, 'withdrawal amount must be smaller than the channel deposit');
        require (withdrawnBalances[key] < _balance, 'invalid balance');
        
        uint256 remainingBalance = _balance - withdrawnBalances[key];
        withdrawnBalances[key] = _balance;

        (msg.sender).transfer(remainingBalance);
        emit ChannelWithdraw(sender, msg.sender, _openBlockNumber, remainingBalance);    
    }

    /**
     * @notice Function called by the sender, receiver or a delegate, with all the needed signatures to close the channel and settle immediately
     * @param _receiver Server side of transfer
     * @param _openBlockNumber The block number at which a channel between the sender and receiver was created.
     * @param _balance Partial or total amount owed by the sender to the receiver
     * @param _balanceMsgSig The balance message signed by the sender
     * @param _closingSig The receiver's signed balance message, containing the sender's address
     */
    function cooperativeClose(
        address _receiver,
        uint256 _openBlockNumber,
        uint192 _balance,
        bytes _balanceMsgSig,
        bytes _closingSig)
    external {
        // Derive sender address from signed balance proof
        address sender = extractBalanceProofSignature(
            _receiver,
            _openBlockNumber,
            _balance,
            _balanceMsgSig
        );

        // Derive receiver address from closing signature
        address receiver = extractClosingSignature(
            sender,
            _openBlockNumber,
            _balance,
            _closingSig
        );
        require(receiver == _receiver, 'invalid signatures');

        // Both signatures have been verified and the channel can be settled.
        settleChannel(sender, receiver, _openBlockNumber, _balance);
    }

    /**
     * @notice Sender requests the closing of the channel and starts the challenge period - This can only happen once
     * @param _receiver Server side of transfer
     * @param _openBlockNumber The block number at which a channel between the sender and receiver was created.
     * @param _balance Partial or total amount owed by the sender to the receiver
     */
    function uncooperativeClose(
        address _receiver,
        uint256 _openBlockNumber,
        uint256 _balance)
    external {
        bytes32 key = getKey(msg.sender, _receiver, _openBlockNumber);

        require(channels[key].openBlockNumber > 0, 'channel does not exist');
        require(closingRequests[key].settleBlockNumber == 0, 'challenge period already started');
        require(_balance <= channels[key].deposit, 'invalid balance');

        // Mark channel as closed
        closingRequests[key].settleBlockNumber = block.number + challengePeriod;
        require(closingRequests[key].settleBlockNumber > block.number, 'challenge period not set correctly');
        closingRequests[key].closingBalance = _balance;
        emit ChannelCloseRequested(msg.sender, _receiver, _openBlockNumber, _balance);
    }

    /**
     * @notice Function called by the sender after the challenge period has ended, in order to settle and delete the channel, in case the receiver has not closed the channel himself
     * @param _receiver Server side of transfer
     * @param _openBlockNumber The block number at which a channel between the sender and receiver was created
     */
    function settle(address _receiver, uint256 _openBlockNumber) external {
        bytes32 key = getKey(msg.sender, _receiver, _openBlockNumber);

        // Make sure an uncooperativeClose has been initiated
        require(closingRequests[key].settleBlockNumber > 0, 'challenge period has not been started');

        // Make sure the challenge_period has ended
	    require(block.number > closingRequests[key].settleBlockNumber, 'challenge period still active');

        settleChannel(msg.sender, _receiver, _openBlockNumber,
            closingRequests[key].closingBalance
        );
    }

    /**
     * @notice Function for retrieving information about a channel.
     * @param _sender address that want to send the micro-payment
     * @param _receiver address that is to receive the micro-payment
     * @param _openBlockNumber the block number at which the channel was created
     * @return Channel information: unique_identifier, deposit, settleBlockNumber, closingBalance, withdrawnBalance
     */
    function getChannelInfo(
        address _sender,
        address _receiver,
        uint256 _openBlockNumber)
    external view returns (bytes32, uint256, uint256, uint256, uint256) {
        bytes32 key = getKey(_sender, _receiver, _openBlockNumber);
        require(channels[key].openBlockNumber > 0, 'channel does not exist');

        return (
            key,
            channels[key].deposit,
            closingRequests[key].settleBlockNumber,
            closingRequests[key].closingBalance,
            withdrawnBalances[key]
        );
    }

    /*
     *  Public functions
     */

    /**
     * @notice can only be called by the owner to add trusted contract addresses
     * @param _trustedContracts Array of contract addresses that can be trusted to open and top up channels on behalf of a sender
     */
    function addTrustedContracts(address[] _trustedContracts) onlyOwner public {
    	for (uint256 i = 0; i < _trustedContracts.length; i++) {
            if (_addressHasCode(_trustedContracts[i])) {
                trustedContracts[_trustedContracts[i]] = true;
                emit TrustedContract(_trustedContracts[i], true);
            }
        }
    }

    /**
     * @notice can only be called by the owner to remove trusted contract addresses
     * @param _trustedContracts Array of contract addresses that can no longer be trusted to open and top up channels on behalf of a sender
     */
    function removeTrustedContracts(address[] _trustedContracts) onlyOwner public {
    	for (uint256 i = 0; i < _trustedContracts.length; i++) {
            if (trustedContracts[_trustedContracts[i]]) {
                trustedContracts[_trustedContracts[i]] = false;
                emit TrustedContract(_trustedContracts[i], false);
            }
        }
    }

    /**
     * @notice can only be called by the owner to remove trusted contract addresses
     * @param _sender address that want to send the micro-payment
     * @param _receiver address that is to receive the micro-payment
     * @param _openBlockNumber the block number at which the channel was created
     */
    function getKey(
        address _sender,
        address _receiver,
        uint256 _openBlockNumber)
    public pure returns (bytes32 data) {
        return keccak256(abi.encodePacked(
        	_sender, 
        	_receiver, 
        	_openBlockNumber
        ));
    }

    /**
     * @notice Returns the sender address extracted from the balance proof
     * @dev Works with eth_signTypedData https://github.com/ethereum/EIPs/pull/712
     * @param _receiver Address that is to receive the micro-payment
     * @param _openBlockNumber Block number at which the channel was created
     * @param _balance The amount owed by the sender to the receiver
     * @param _balanceMsgSig The balance message signed by the sender
     * @return Address of the balance proof signer
     */
    function extractBalanceProofSignature(
        address _receiver,
        uint256 _openBlockNumber,
        uint256 _balance,
        bytes _balanceMsgSig)
    public view returns(address) {
    	bytes32 message_hash = keccak256(abi.encodePacked(
            abi.encodePacked(
                'string message_id',
                'address receiver',
                'uint32 block_created',
                'uint192 balance',
                'address contract'
            ),
            abi.encodePacked(
                'Sender balance proof signature',
                _receiver,
                _openBlockNumber,
                _balance,
                address(this)
            )
        ));

        // Derive address from signature
        address signer = ECDSA.recover(message_hash, _balanceMsgSig);
        return signer;
    }

    /**
     * @notice Returns the receiver address extracted from the closing signature
     * @dev Works with eth_signTypedData https://github.com/ethereum/EIPs/pull/712
     * @param _sender Address that is sending the micro-payment
     * @param _openBlockNumber Block number at which the channel was created
     * @param _balance The amount owed by the sender to the receiver
     * @param _closingSig The receiver's signed balance message, containing the sender's address
     * @return Address of the closing signature signer
     */
    function extractClosingSignature(
        address _sender,
        uint256 _openBlockNumber,
        uint256 _balance,
        bytes _closingSig)
    public view returns (address) {
        // The variable names from below will be shown to the sender when signing
        // the balance proof, so they have to be kept in sync with the Dapp client.
        // The hashed strings should be kept in sync with this function's parameters
        // (variable names and types).
        // ! Note that EIP712 might change how hashing is done, triggering a
        // new contract deployment with updated code.
        bytes32 message_hash = keccak256(abi.encodePacked(
            abi.encodePacked(
                'string message_id',
                'address sender',
                'uint32 block_created',
                'uint192 balance',
                'address contract'
            ),
            abi.encodePacked(
                'Receiver closing signature',
                _sender,
                _openBlockNumber,
                _balance,
                address(this)
            )
        ));

        // Derive address from signature
        address signer = ECDSA.recover(message_hash, _closingSig);
        return signer;
    }

    /*
     *  Private functions
     */

    /**
     * @notice can only be called by the owner to remove trusted contract addresses
     * @param _sender address that want to send the micro-payment
     * @param _receiver address that is to receive the micro-payment
     * @param _deposit amount of ETH escrowed by the sender
     */
    function createChannelPrivate(
        address _sender,
        address _receiver,
        uint256 _deposit)
    private {
    	// set a 1 ETH deposit limit until fully tested for security violations
    	require(_deposit <= 1 ether, 'deposit limit crossed');

        // Create unique identifier from sender, receiver and current block number
        bytes32 key = getKey(_sender, _receiver, block.number);

        require(channels[key].deposit == 0);
        require(channels[key].openBlockNumber == 0);
        require(closingRequests[key].settleBlockNumber == 0);

        // Store channel information
        channels[key] = Channel({deposit: _deposit, openBlockNumber: block.number});
        emit ChannelCreated(_sender, _receiver, _deposit);
    }

    /**
     * @notice can only be called by the owner to remove trusted contract addresses
     * @param _sender address that want to send the micro-payment
     * @param _receiver address that is to receive the micro-payment
     * @param _openBlockNumber Block number at which the channel was created
     * @param _addedDeposit The added deposit with which the current deposit is increased
     */
    function updateInternalBalanceStructs(
        address _sender,
        address _receiver,
        uint256 _openBlockNumber,
        uint256 _addedDeposit)
    private {
    	require(_addedDeposit > 0, 'topUp amount must not be zero');
        require(_openBlockNumber > 0, 'invalid openBlockNumber');

        bytes32 key = getKey(_sender, _receiver, _openBlockNumber);

        require(channels[key].openBlockNumber > 0, "channel does not exist");
        require(closingRequests[key].settleBlockNumber == 0, "channel already closed");
        require(channels[key].deposit + _addedDeposit <= 1 ether, "channel limit exceeded");

        channels[key].deposit += _addedDeposit;
        assert(channels[key].deposit >= _addedDeposit);
        emit ChannelToppedUp(_sender, _receiver, _openBlockNumber, _addedDeposit);
    }

    /**
     * @notice Deletes the channel and settles by transfering the balance to the receiver and the rest of the deposit back to the sender
     * @param _sender address that want to send the micro-payment
     * @param _receiver address that is to receive the micro-payment
     * @param _openBlockNumber Block number at which the channel was created
     * @param _balance The amount owed by the sender to the receiver
     */
    function settleChannel(
        address _sender,
        address _receiver,
        uint256 _openBlockNumber,
        uint256 _balance)
    private {
        bytes32 key = getKey(_sender, _receiver, _openBlockNumber);
        Channel memory channel = channels[key];

        require(channel.openBlockNumber > 0, 'channel does not exist');
        require(_balance <= channel.deposit, 'balance must be less than channel deposit');
        require(withdrawnBalances[key] <= _balance, 'invalid balance');

        // Remove closed channel structures
        // channel.openBlockNumber will become 0
        // Change state before transfer call
        delete channels[key];
        delete closingRequests[key];

        // Send the unwithdrawn _balance to the receiver
        uint256 receiverRemainingAmount = _balance - withdrawnBalances[key];
        _receiver.transfer(receiverRemainingAmount);

        // Send deposit - balance back to sender
        _sender.transfer(channel.deposit - _balance);

        emit ChannelSettled(
            _sender,
            _receiver,
            _openBlockNumber,
            _balance,
            receiverRemainingAmount
        );
    }
    
    /*
     *  Internal functions
     */

    /**
     * @notice Creates a new channel between a sender and a receiver
     * @param data Bytes received
     * @param offset Number of bytes to offset
     * @return Extracted address
     */
    function addressFromBytes (bytes data, uint256 offset) internal pure returns (address) {
        bytes20 extractedAddress;
        assembly {
            extractedAddress := mload(add(data, offset))
        }
        return address(extractedAddress);
    }

    /**
     * @notice used to verify if an address has some contract code
     * @param _contract is the address of the contract
     * @return True if a contract exists, false otherwise
     */
    function _addressHasCode(address _contract) internal view returns (bool) {
        uint size;
        assembly {
            size := extcodesize(_contract)
        }
        return size > 0;
    }
}