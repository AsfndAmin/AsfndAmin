// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

contract MyToken is ERC721, Ownable {
    using Counters for Counters.Counter;

    address signerAddress;
    string public baseUriExtended;
    uint256 mintFee;

    Counters.Counter private _tokenIdCounter;

    mapping(address => bool) _minted;

    event TokenMinted(address, uint256);
    event SignerChanged(address);

    constructor(address _signerAddress) ERC721("MyToken", "MTK") {
        signerAddress = _signerAddress;
    }

    function safeMint(bytes memory signature) external payable {
        require(!_minted[msg.sender], "already minted");
        require(msg.value == mintFee, "fee error"); 
        //signature verification functionality
        require(verify(msg.sender, signature), "INVALID_SIGNATURE");
        _tokenIdCounter.increment();
        uint256 tokenId = _tokenIdCounter.current();
        _safeMint(msg.sender, tokenId);
        _minted[msg.sender] = true;
        emit TokenMinted(msg.sender, tokenId);
    }

    //getting msg hash to generate signature off chian
    function getMessageHash(
        address receiver
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(receiver));
    }

    //signer functioanlity
    function getEthSignedMessageHash(bytes32 _messageHash)
        public
        pure
        returns (bytes32)
    {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    function verify(
        address receiver,
        bytes memory signature
    ) public view returns (bool) {
        bytes32 messageHash = getMessageHash(receiver);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        return recoverSigner(ethSignedMessageHash, signature) == signerAddress;
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature)
        public
        pure
        returns (address)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        public
        pure
        returns (
            bytes32 r,
            bytes32 s,
            uint8 v
        )
    {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature
            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature
            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly return (r, s, v)
    }

    
    function setSignerAddress(address _address) external onlyOwner {
        signerAddress = _address;
        emit SignerChanged(_address); 
    }

    function setBaseUri(string memory _baseUri) public onlyOwner{
        baseUriExtended = _baseUri;
    }

    
    function setMintFee(uint256 _fee) public onlyOwner{
        mintFee = _fee;
    }

     function _baseURI() internal view override returns (string memory) {
        return baseUriExtended;
    }
}
