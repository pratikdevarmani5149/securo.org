"use client";

import type { ReactNode } from "react";
import { StarknetConfig, publicProvider } from "@starknet-react/core";
import { mainnet, sepolia } from "@starknet-react/chains";
import { argent, braavos } from "@starknet-react/core";

export function Providers({ children }: { children: ReactNode }) {
  return (
    <StarknetConfig
      chains={[sepolia, mainnet]}
      provider={publicProvider()}
      connectors={[argent(), braavos()]}
      autoConnect
    >
      {children}
    </StarknetConfig>
  );
}

