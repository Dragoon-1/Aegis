// hardhat.config.js
require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: { enabled: true, runs: 200 }
    }
  },
  networks: {
    // Local testing
    hardhat: {
      chainId: 31337
    },
    // Polygon Amoy testnet (free MATIC from faucet.polygon.technology)
    amoy: {
      url:      process.env.POLYGON_RPC_URL || "https://rpc-amoy.polygon.technology/",
      accounts: process.env.POLYGON_PRIVATE_KEY ? [process.env.POLYGON_PRIVATE_KEY] : [],
      chainId:  80002
    },
    // Polygon mainnet (real MATIC required — use for production)
    polygon: {
      url:      "https://polygon-rpc.com",
      accounts: process.env.POLYGON_PRIVATE_KEY ? [process.env.POLYGON_PRIVATE_KEY] : [],
      chainId:  137
    }
  },
  etherscan: {
    apiKey: {
      polygon:     process.env.POLYGONSCAN_API_KEY || "",
      polygonAmoy: process.env.POLYGONSCAN_API_KEY || ""
    }
  }
};
