// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { ibe, ace } from '@aptos-labs/ace-sdk';
import express, { Request, Response } from 'express';
import cors from 'cors';
import { randomUUID } from 'crypto';

export interface Options {
  port: number;
}

export interface WorkerContext {
  ibeMsk: ibe.MasterPrivateKey;
  ibeMpk: ibe.MasterPublicKey;
  rpcConfig: ace.RpcConfig;
}

function createRequestHandler(ctx: WorkerContext) {
  return async (req: Request, res: Response): Promise<void> => {
    const sessionId = randomUUID().slice(0, 8);
    console.log(`[${sessionId}]: BEGIN`);

    let request: ace.RequestForDecryptionKey;
    try {
      const bodyHex = typeof req.body === 'string' ? req.body : String(req.body);
      const parseResult = ace.RequestForDecryptionKey.fromHex(bodyHex);
      if (!parseResult.isOk) {
        throw parseResult.errValue;
      }
      request = parseResult.okValue!;
    } catch (error) {
      res.status(400).send('Could not parse request.');
      console.warn(`[${sessionId}]: DENIED: could not parse request: ${error}`);
      return;
    }

    console.log(`[${sessionId}]: Received decryption key request`);

    try {
      const extractResult = await ace.verifyAndExtract({
        ibeMsk: ctx.ibeMsk,
        contractId: request.contractId,
        domain: request.domain,
        proof: request.proof,
        rpcConfig: ctx.rpcConfig
      });

      if (!extractResult.isOk) {
        console.warn(`[${sessionId}]: DENIED: verification failed: ${extractResult.errValue}`);
        console.warn(`[${sessionId}]: Extra info: ${JSON.stringify(extractResult.extra, null, 2)}`);
        res.status(400).send('Could not reveal decryption key: verification failed');
        return;
      }

      const extractedKey = extractResult.okValue!;
      console.log(`[${sessionId}]: APPROVED`);
      res.status(200).send(extractedKey.toHex());
    } catch (error) {
      console.warn(`[${sessionId}]: DENIED: could not reveal decryption key: ${error}`);
      res.status(400).send('Could not reveal decryption key');
    }
  };
}

export async function run(options: Options): Promise<void> {
  // Check required environment variables
  const requiredEnvVars = ['IBE_MSK'];
  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      throw new Error(`Missing required environment variable: ${envVar}`);
    }
  }

  // Configure RPC endpoints from environment variables
  const rpcConfig: ace.RpcConfig = {
    aptos: {},
    solana: {},
  };

  // Aptos endpoints and API keys
  if (process.env.APTOS_MAINNET_API_ENDPOINT || process.env.APTOS_MAINNET_API_KEY) {
    rpcConfig.aptos!.mainnet = {
      endpoint: process.env.APTOS_MAINNET_API_ENDPOINT,
      apiKey: process.env.APTOS_MAINNET_API_KEY,
    };
  }
  if (process.env.APTOS_TESTNET_API_ENDPOINT || process.env.APTOS_TESTNET_API_KEY) {
    rpcConfig.aptos!.testnet = {
      endpoint: process.env.APTOS_TESTNET_API_ENDPOINT,
      apiKey: process.env.APTOS_TESTNET_API_KEY,
    };
  }
  if (process.env.APTOS_LOCALNET_API_ENDPOINT) {
    rpcConfig.aptos!.localnet = {
      endpoint: process.env.APTOS_LOCALNET_API_ENDPOINT,
    };
  }

  // Solana endpoints
  if (process.env.SOLANA_MAINNET_API_ENDPOINT) {
    rpcConfig.solana!['mainnet-beta'] = process.env.SOLANA_MAINNET_API_ENDPOINT;
  }
  if (process.env.SOLANA_TESTNET_API_ENDPOINT) {
    rpcConfig.solana!.testnet = process.env.SOLANA_TESTNET_API_ENDPOINT;
  }
  if (process.env.SOLANA_DEVNET_API_ENDPOINT) {
    rpcConfig.solana!.devnet = process.env.SOLANA_DEVNET_API_ENDPOINT;
  }
  if (process.env.SOLANA_LOCALNET_API_ENDPOINT) {
    rpcConfig.solana!.localnet = process.env.SOLANA_LOCALNET_API_ENDPOINT;
  }

  // Parse IBE master secret key from environment
  const ibeMskHex = process.env.IBE_MSK!.startsWith('0x') 
    ? process.env.IBE_MSK!.slice(2) 
    : process.env.IBE_MSK!;
  
  const ibeMskResult = ibe.MasterPrivateKey.fromHex(ibeMskHex);
  if (!ibeMskResult.isOk) {
    throw new Error(`Failed to parse IBE_MSK: ${ibeMskResult.errValue}`);
  }
  const ibeMsk = ibeMskResult.okValue!;

  // Derive public key from master secret key
  const ibeMpkResult = ibe.derivePublicKey(ibeMsk);
  if (!ibeMpkResult.isOk) {
    throw new Error(`Failed to derive IBE public key: ${ibeMpkResult.errValue}`);
  }
  const ibeMpk = ibeMpkResult.okValue!;

  // Validate public key if provided in environment variables
  if (process.env.IBE_MPK) {
    const providedIbeMpkHex = process.env.IBE_MPK.startsWith('0x') 
      ? process.env.IBE_MPK.slice(2) 
      : process.env.IBE_MPK;
    if (ibeMpk.toHex() !== providedIbeMpkHex) {
      throw new Error('IBE_MPK environment variable does not match the derived master public key from IBE_MSK');
    }
  }

  console.log(`Worker Configuration:`);
  console.log(`  IBE_MPK: 0x${ibeMpk.toHex()}`);

  // Log configured RPC endpoints
  if (rpcConfig.aptos && Object.keys(rpcConfig.aptos).length > 0) {
    console.log(`  Aptos RPC Config:`);
    for (const [network, config] of Object.entries(rpcConfig.aptos)) {
      if (config) {
        const parts = [];
        if (config.endpoint) parts.push(`endpoint=${config.endpoint}`);
        if (config.apiKey) parts.push(`apiKey=***`);
        if (parts.length > 0) console.log(`    ${network}: ${parts.join(', ')}`);
      }
    }
  }
  if (rpcConfig.solana && Object.keys(rpcConfig.solana).length > 0) {
    console.log(`  Solana RPC Endpoints:`);
    for (const [network, endpoint] of Object.entries(rpcConfig.solana)) {
      if (endpoint) console.log(`    ${network}: ${endpoint}`);
    }
  }

  const ctx: WorkerContext = { ibeMsk, ibeMpk, rpcConfig };

  // Start HTTP server
  const app = express();
  app.use(cors());
  app.use(express.text());

  // Main decryption endpoint
  app.post('/', createRequestHandler(ctx));

  // Health check
  app.get('/', (_req: Request, res: Response) => {
    res.status(200).send('ACE Worker OK');
  });

  // Return the IBE master public key
  app.get('/ibe_mpk', (_req: Request, res: Response) => {
    res.status(200).send(ibeMpk.toHex());
  });

  // Health check endpoint
  app.get('/health', (_req: Request, res: Response) => {
    res.status(200).json({ status: 'ok', timestamp: Date.now() });
  });

  app.listen(options.port, () => {
    console.log(`ACE Worker listening on port ${options.port}`);
  });
}

