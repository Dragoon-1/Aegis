// scripts/deploy.js
const hre = require("hardhat");
const fs  = require("fs");
const path = require("path");

async function main() {
  console.log("Deploying AegisThreatIntel to", hre.network.name, "...");

  const [deployer] = await hre.ethers.getSigners();
  console.log("Deployer wallet:", deployer.address);

  const balance = await deployer.provider.getBalance(deployer.address);
  console.log("Wallet balance:", hre.ethers.formatEther(balance), "MATIC");

  if (balance === 0n) {
    console.error("ERROR: Wallet has no MATIC. Get testnet MATIC from https://faucet.polygon.technology");
    process.exit(1);
  }

  // Deploy
  const AegisThreatIntel = await hre.ethers.getContractFactory("AegisThreatIntel");
  const contract = await AegisThreatIntel.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("\n✅ AegisThreatIntel deployed!");
  console.log("   Contract address:", address);
  console.log("   Network:         ", hre.network.name);
  console.log("   Tx hash:         ", contract.deploymentTransaction()?.hash);

  // ── Save address to file — backend and Android app will read from here ──
  const deployInfo = {
    network:         hre.network.name,
    contractAddress: address,
    deployedAt:      new Date().toISOString(),
    deployer:        deployer.address,
  };

  const outputPath = path.join(__dirname, "..", "deployed.json");
  fs.writeFileSync(outputPath, JSON.stringify(deployInfo, null, 2));
  console.log("\n   Saved to deployed.json — copy CONTRACT_ADDRESS to your .env");

  // ── Verify on Polygonscan (if not local) ─────────────────────────────────
  if (hre.network.name !== "hardhat" && hre.network.name !== "localhost") {
    console.log("\nWaiting 30s before verification...");
    await new Promise(r => setTimeout(r, 30_000));
    try {
      await hre.run("verify:verify", { address, constructorArguments: [] });
      console.log("✅ Contract verified on Polygonscan");
    } catch (e) {
      console.log("⚠️  Verification failed (non-critical):", e.message);
    }
  }
}

main().catch(err => { console.error(err); process.exit(1); });
