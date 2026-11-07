import { needsAllowHttp, nodeEnv, splitScope } from "./nodes";

describe("nodes helpers", () => {
  it("разбирает сети узла через запятую, пробелы и строки", () => {
    expect(splitScope("10.1.0.0/24, 10.2.0.1-10.2.0.9\n192.168.1.5")).toEqual([
      "10.1.0.0/24",
      "10.2.0.1-10.2.0.9",
      "192.168.1.5",
    ]);
  });

  it("собирает .env.node", () => {
    expect(nodeEnv("https://scanner.corp.local", "snode_x", ["10.1.0.0/24", "10.2.0.0/24"])).toBe(
      "SCANNER_NODE_SERVER=https://scanner.corp.local\nSCANNER_NODE_TOKEN=snode_x\nSCANNER_NODE_ALLOWLIST=10.1.0.0/24,10.2.0.0/24",
    );
  });

  it("предупреждает о центре без TLS, кроме localhost", () => {
    expect(needsAllowHttp("http://scanner.corp.local:18080")).toBe(true);
    expect(needsAllowHttp("https://scanner.corp.local")).toBe(false);
    expect(needsAllowHttp("http://localhost:5173")).toBe(false);
    expect(needsAllowHttp("http://127.0.0.1:18080")).toBe(false);
  });
});
