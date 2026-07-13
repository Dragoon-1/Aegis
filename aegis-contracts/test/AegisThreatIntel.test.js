const { expect }  = require("chai");
const { ethers }  = require("hardhat");

/**
 * AegisThreatIntel Smart Contract — Test Suite
 * Run with: npx hardhat test
 */
describe("AegisThreatIntel", function () {

  let contract;
  let owner, user1, user2, user3;

  // Sample threat hashes (SHA-256 of fake indicators)
  const HASH_URL    = ethers.keccak256(ethers.toUtf8Bytes("https://phishing.example.com"));
  const HASH_PHONE  = ethers.keccak256(ethers.toUtf8Bytes("+911234567890"));
  const HASH_FILE   = ethers.keccak256(ethers.toUtf8Bytes("ransomware_sample_sha256"));
  const HASH_CLEAN  = ethers.keccak256(ethers.toUtf8Bytes("https://google.com"));

  const CATEGORY = { URL: 0, PHONE: 1, FILE_HASH: 2, IP: 3, APP: 4, RANSOMWARE: 5 };

  beforeEach(async function () {
    [owner, user1, user2, user3] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("AegisThreatIntel");
    contract      = await Factory.deploy();
    await contract.waitForDeployment();
  });

  // ── Deployment ──────────────────────────────────────────────────────────────

  describe("Deployment", function () {
    it("sets the correct owner", async function () {
      expect(await contract.owner()).to.equal(owner.address);
    });

    it("starts unpaused with zero threats", async function () {
      expect(await contract.paused()).to.be.false;
      expect(await contract.totalThreats()).to.equal(0);
    });
  });

  // ── reportThreat ────────────────────────────────────────────────────────────

  describe("reportThreat", function () {
    it("records the first report correctly", async function () {
      await contract.connect(user1).reportThreat(HASH_URL, CATEGORY.URL, 4, "IN");

      const [isThreat, count, severity, category] = await contract.checkThreat(HASH_URL);
      // Below community minimum (3) — not visible yet
      expect(isThreat).to.be.false;
      expect(await contract.totalThreats()).to.equal(1);
    });

    it("increments report count on subsequent reports", async function () {
      await contract.connect(user1).reportThreat(HASH_URL, CATEGORY.URL, 3, "IN");
      await contract.connect(user2).reportThreat(HASH_URL, CATEGORY.URL, 4, "IN");
      await contract.connect(user3).reportThreat(HASH_URL, CATEGORY.URL, 4, "IN");

      // Now at 3 reports — meets MIN_REPORTS_PUBLIC
      const [isThreat, count, severity] = await contract.checkThreat(HASH_URL);
      expect(isThreat).to.be.true;
      expect(count).to.equal(3);
      expect(severity).to.equal(4); // max severity
    });

    it("escalates max severity upward but never downward", async function () {
      await contract.connect(user1).reportThreat(HASH_PHONE, CATEGORY.PHONE, 2, "IN");
      await contract.connect(user2).reportThreat(HASH_PHONE, CATEGORY.PHONE, 5, "IN");
      await contract.connect(user3).reportThreat(HASH_PHONE, CATEGORY.PHONE, 1, "IN");

      const [, , severity] = await contract.checkThreat(HASH_PHONE);
      expect(severity).to.equal(5); // kept the highest
    });

    it("emits NewThreatDiscovered on first report", async function () {
      await expect(
        contract.connect(user1).reportThreat(HASH_FILE, CATEGORY.FILE_HASH, 4, "US")
      ).to.emit(contract, "NewThreatDiscovered")
       .withArgs(HASH_FILE, CATEGORY.FILE_HASH, "US");
    });

    it("emits ThreatReported on every report", async function () {
      await expect(
        contract.connect(user1).reportThreat(HASH_URL, CATEGORY.URL, 3, "IN")
      ).to.emit(contract, "ThreatReported");
    });

    it("reverts on empty hash", async function () {
      await expect(
        contract.connect(user1).reportThreat(ethers.ZeroHash, CATEGORY.URL, 3, "IN")
      ).to.be.revertedWith("Empty hash");
    });

    it("reverts on invalid severity (0 or 6)", async function () {
      await expect(
        contract.connect(user1).reportThreat(HASH_URL, CATEGORY.URL, 0, "IN")
      ).to.be.reverted;
      await expect(
        contract.connect(user1).reportThreat(HASH_URL, CATEGORY.URL, 6, "IN")
      ).to.be.reverted;
    });

    it("reverts when paused", async function () {
      await contract.connect(owner).setPaused(true);
      await expect(
        contract.connect(user1).reportThreat(HASH_URL, CATEGORY.URL, 3, "IN")
      ).to.be.revertedWith("Contract paused");
    });
  });

  // ── checkThreat ─────────────────────────────────────────────────────────────

  describe("checkThreat", function () {
    it("returns false for unknown hashes", async function () {
      const [isThreat] = await contract.checkThreat(HASH_CLEAN);
      expect(isThreat).to.be.false;
    });

    it("returns false below minimum report threshold", async function () {
      await contract.connect(user1).reportThreat(HASH_URL, CATEGORY.URL, 4, "IN");
      await contract.connect(user2).reportThreat(HASH_URL, CATEGORY.URL, 4, "IN");
      // Only 2 reports — MIN_REPORTS_PUBLIC is 3
      const [isThreat] = await contract.checkThreat(HASH_URL);
      expect(isThreat).to.be.false;
    });

    it("returns true once minimum threshold is met", async function () {
      for (const signer of [user1, user2, user3]) {
        await contract.connect(signer).reportThreat(HASH_URL, CATEGORY.URL, 3, "IN");
      }
      const [isThreat, count] = await contract.checkThreat(HASH_URL);
      expect(isThreat).to.be.true;
      expect(count).to.equal(3);
    });
  });

  // ── batchCheckThreats ───────────────────────────────────────────────────────

  describe("batchCheckThreats", function () {
    it("correctly flags known threats in a batch", async function () {
      // Make HASH_URL a confirmed threat (3+ reports)
      for (const signer of [user1, user2, user3]) {
        await contract.connect(signer).reportThreat(HASH_URL, CATEGORY.URL, 4, "IN");
      }

      const hashes = [HASH_URL, HASH_CLEAN, HASH_FILE];
      const [flags, severities] = await contract.batchCheckThreats(hashes);

      expect(flags[0]).to.be.true;   // HASH_URL — confirmed threat
      expect(flags[1]).to.be.false;  // HASH_CLEAN — unknown
      expect(flags[2]).to.be.false;  // HASH_FILE — below threshold
      expect(severities[0]).to.equal(4);
      expect(severities[1]).to.equal(0);
    });
  });

  // ── ThreatEscalated event ───────────────────────────────────────────────────

  describe("Police escalation", function () {
    it("emits ThreatEscalated when POLICE_THRESHOLD is reached", async function () {
      const POLICE_THRESHOLD = 100;
      const signers = await ethers.getSigners();

      // We only have ~20 signers in Hardhat by default, so we deploy
      // a test-version with a lower threshold
      const Factory  = await ethers.getContractFactory("AegisThreatIntel");
      const testContract = await Factory.deploy();

      // Report 100 times using the same user (simplified for test)
      // In production, each report should be from a unique device address
      let escalationEmitted = false;
      for (let i = 0; i < POLICE_THRESHOLD; i++) {
        const tx = await testContract.connect(user1).reportThreat(
          HASH_URL, CATEGORY.URL, 4, "IN"
        );
        const receipt = await tx.wait();
        if (receipt.logs.some(log => {
          try {
            return testContract.interface.parseLog(log)?.name === "ThreatEscalated";
          } catch { return false; }
        })) {
          escalationEmitted = true;
          break;
        }
      }
      expect(escalationEmitted).to.be.true;
    });
  });

  // ── getRecentThreats ────────────────────────────────────────────────────────

  describe("getRecentThreats", function () {
    it("returns threats in paginated order", async function () {
      // Add 3 different threats
      for (const signer of [user1, user2, user3]) {
        await contract.connect(signer).reportThreat(HASH_URL,   CATEGORY.URL,       3, "IN");
        await contract.connect(signer).reportThreat(HASH_PHONE, CATEGORY.PHONE,     4, "IN");
        await contract.connect(signer).reportThreat(HASH_FILE,  CATEGORY.FILE_HASH, 5, "IN");
      }

      const [hashes, categories, severities, counts] =
        await contract.getRecentThreats(0, 10);

      expect(hashes.length).to.equal(3);
      expect(counts[0]).to.equal(3);
    });

    it("handles empty result gracefully", async function () {
      const [hashes] = await contract.getRecentThreats(0, 10);
      expect(hashes.length).to.equal(0);
    });
  });

  // ── Admin functions ─────────────────────────────────────────────────────────

  describe("Admin", function () {
    it("owner can pause and unpause", async function () {
      await contract.connect(owner).setPaused(true);
      expect(await contract.paused()).to.be.true;

      await contract.connect(owner).setPaused(false);
      expect(await contract.paused()).to.be.false;
    });

    it("non-owner cannot pause", async function () {
      await expect(
        contract.connect(user1).setPaused(true)
      ).to.be.revertedWith("Not owner");
    });

    it("owner can transfer ownership", async function () {
      await contract.connect(owner).transferOwnership(user1.address);
      expect(await contract.owner()).to.equal(user1.address);
    });

    it("cannot transfer to zero address", async function () {
      await expect(
        contract.connect(owner).transferOwnership(ethers.ZeroAddress)
      ).to.be.revertedWith("Zero address");
    });
  });

  // ── Gas estimates ───────────────────────────────────────────────────────────

  describe("Gas estimates", function () {
    it("first reportThreat costs under 120,000 gas", async function () {
      const tx      = await contract.connect(user1).reportThreat(HASH_URL, CATEGORY.URL, 3, "IN");
      const receipt = await tx.wait();
      console.log("    First report gas:", receipt.gasUsed.toString());
      expect(receipt.gasUsed).to.be.lessThan(120_000n);
    });

    it("subsequent reportThreat costs under 60,000 gas", async function () {
      await contract.connect(user1).reportThreat(HASH_URL, CATEGORY.URL, 3, "IN");
      const tx      = await contract.connect(user2).reportThreat(HASH_URL, CATEGORY.URL, 4, "IN");
      const receipt = await tx.wait();
      console.log("    Update report gas:", receipt.gasUsed.toString());
      expect(receipt.gasUsed).to.be.lessThan(60_000n);
    });
  });
});
