import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createStorage } from "../storage.js";

const message = id => ({ id, sender:"Campus", subject:`Message ${id}`, preview:"Private preview", date:new Date().toISOString(), initials:"CA", priority:"critical", reason:"Test" });

test("email cache remains isolated by account and deletion is scoped", async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "campus-inbox-test-"));
  const storage = await createStorage({ dataDirectory:directory });
  t.after(async () => { await storage.close(); fs.rmSync(directory, { recursive:true, force:true }); });

  await storage.writeEmailCache("owner-a", { shared:message("shared"), a:message("a") });
  await storage.writeEmailCache("owner-b", { shared:{ ...message("shared"), subject:"Owner B copy" }, b:message("b") });

  const ownerA = await storage.readEmailCache("owner-a");
  const ownerB = await storage.readEmailCache("owner-b");
  assert.deepEqual(Object.keys(ownerA).sort(), ["a", "shared"]);
  assert.deepEqual(Object.keys(ownerB).sort(), ["b", "shared"]);
  assert.equal(ownerA.shared.subject, "Message shared");
  assert.equal(ownerB.shared.subject, "Owner B copy");

  assert.equal(await storage.deleteOwnerData("owner-a"), 2);
  assert.deepEqual(await storage.readEmailCache("owner-a"), {});
  assert.deepEqual(Object.keys(await storage.readEmailCache("owner-b")).sort(), ["b", "shared"]);
});
