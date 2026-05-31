// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * generate_totp MCP Tool
 *
 * Generates 6-digit TOTP codes for authentication.
 * Replaces tools/generate-totp-standalone.mjs bash script.
 * Based on RFC 6238 (TOTP) and RFC 4226 (HOTP).
 */

import { tool } from '@anthropic-ai/claude-agent-sdk';
import { createHmac } from 'crypto';
import { z } from 'zod';
import { createToolResult, type ToolResult, type GenerateTotpResponse } from '../types/tool-responses.js';
import { base32Decode, validateTotpSecret } from '../validation/totp-validator.js';
import { createCryptoError, createGenericError } from '../utils/error-formatter.js';

/**
 * Supported HMAC hash algorithms for OTP generation.
 *
 * SECURITY / COMPLIANCE NOTE -- why 'sha1' remains the DEFAULT:
 *   RFC 6238 (TOTP) and RFC 4226 (HOTP) define HMAC-SHA1 as the default
 *   construction. The overwhelming majority of authenticator apps (Google
 *   Authenticator, Authy, etc.) and target systems ONLY support SHA-1.
 *   Because Dapper uses these codes to authenticate against EXTERNAL target
 *   systems during pentests, the algorithm MUST match what the target expects
 *   -- forcing SHA-256/512 would break MFA against most targets.
 *
 *   Importantly, HMAC-SHA1's security does NOT depend on SHA-1's collision
 *   resistance. The SHA-1 collision attacks cited in security scanners (e.g.
 *   SHAttered) do not weaken HMAC-SHA1, so retaining SHA-1 here is a
 *   compliance/best-practice concern rather than an exploitable break.
 *
 *   The algorithm is therefore made CONFIGURABLE: callers may opt into
 *   SHA-256/512 where the target supports it, while the default stays SHA-1
 *   for interoperability. This is the documented business justification for
 *   retaining SHA-1 (the compensating control from the remediation guidance).
 */
export type OTPAlgorithm = 'sha1' | 'sha256' | 'sha512';

const ALLOWED_ALGORITHMS: readonly OTPAlgorithm[] = ['sha1', 'sha256', 'sha512'];

/** Default per RFC 6238/4226 for interoperability (see OTPAlgorithm docs). */
export const DEFAULT_OTP_ALGORITHM: OTPAlgorithm = 'sha1';

/**
 * Validates and normalizes the requested HMAC algorithm, falling back to the
 * SHA-1 default for interoperability when none is supplied.
 */
function resolveAlgorithm(algorithm?: string): OTPAlgorithm {
  if (algorithm === undefined) {
    return DEFAULT_OTP_ALGORITHM;
  }
  const normalized = algorithm.toLowerCase();
  if (!ALLOWED_ALGORITHMS.includes(normalized as OTPAlgorithm)) {
    throw new Error(
      `Invalid OTP algorithm "${algorithm}". Allowed values: ${ALLOWED_ALGORITHMS.join(', ')}.`,
    );
  }
  return normalized as OTPAlgorithm;
}

/**
 * Input schema for generate_totp tool
 */
export const GenerateTotpInputSchema = z.object({
  secret: z
    .string()
    .min(1)
    .regex(/^[A-Z2-7]+$/i, 'Must be base32-encoded')
    .describe('Base32-encoded TOTP secret'),
  algorithm: z
    .enum(['sha1', 'sha256', 'sha512'])
    .optional()
    .describe(
      "HMAC hash algorithm (default: 'sha1' for RFC 6238 interoperability with authenticator apps and target systems; use sha256/sha512 only when the target supports it)",
    ),
});

export type GenerateTotpInput = z.infer<typeof GenerateTotpInputSchema>;

/**
 * Generate HOTP code (RFC 4226)
 * Ported from generate-totp-standalone.mjs (lines 74-99)
 */
function generateHOTP(
  secret: string,
  counter: number,
  digits: number = 6,
  algorithm: OTPAlgorithm = DEFAULT_OTP_ALGORITHM,
): string {
  const key = base32Decode(secret);

  // Convert counter to 8-byte buffer (big-endian)
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));

  // Generate HMAC. Default 'sha1' per RFC 4226 -- required for
  // interoperability; HMAC-SHA1 is not weakened by SHA-1 collision attacks
  // (see OTPAlgorithm docs for the full justification).
  const hmac = createHmac(algorithm, key);
  hmac.update(counterBuffer);
  const hash = hmac.digest();

  // Dynamic truncation
  const offset = hash[hash.length - 1]! & 0x0f;
  const code =
    ((hash[offset]! & 0x7f) << 24) |
    ((hash[offset + 1]! & 0xff) << 16) |
    ((hash[offset + 2]! & 0xff) << 8) |
    (hash[offset + 3]! & 0xff);

  // Generate digits
  const otp = (code % Math.pow(10, digits)).toString().padStart(digits, '0');
  return otp;
}

/**
 * Generate TOTP code (RFC 6238)
 * Ported from generate-totp-standalone.mjs (lines 101-106)
 */
function generateTOTP(
  secret: string,
  timeStep: number = 30,
  digits: number = 6,
  algorithm: OTPAlgorithm = DEFAULT_OTP_ALGORITHM,
): string {
  const currentTime = Math.floor(Date.now() / 1000);
  const counter = Math.floor(currentTime / timeStep);
  return generateHOTP(secret, counter, digits, algorithm);
}

/**
 * Get seconds until TOTP code expires
 */
function getSecondsUntilExpiration(timeStep: number = 30): number {
  const currentTime = Math.floor(Date.now() / 1000);
  return timeStep - (currentTime % timeStep);
}

/**
 * generate_totp tool implementation
 */
export async function generateTotp(args: GenerateTotpInput): Promise<ToolResult> {
  try {
    const { secret, algorithm } = args;

    // Validate secret (throws on error)
    validateTotpSecret(secret);

    // Resolve/validate algorithm (defaults to sha1 for interoperability)
    const hashAlgorithm = resolveAlgorithm(algorithm);

    // Generate TOTP code
    const totpCode = generateTOTP(secret, 30, 6, hashAlgorithm);
    const expiresIn = getSecondsUntilExpiration();
    const timestamp = new Date().toISOString();

    // Success response
    const successResponse: GenerateTotpResponse = {
      status: 'success',
      message: 'TOTP code generated successfully',
      totpCode,
      timestamp,
      expiresIn,
    };

    return createToolResult(successResponse);
  } catch (error) {
    // Check if it's a validation/crypto error
    if (error instanceof Error && (error.message.includes('base32') || error.message.includes('TOTP'))) {
      const errorResponse = createCryptoError(error.message, false);
      return createToolResult(errorResponse);
    }

    // Generic error
    const errorResponse = createGenericError(error, false);
    return createToolResult(errorResponse);
  }
}

/**
 * Tool definition for MCP server - created using SDK's tool() function
 */
export const generateTotpTool = tool(
  'generate_totp',
  'Generates 6-digit TOTP code for authentication. Secret must be base32-encoded.',
  GenerateTotpInputSchema.shape,
  generateTotp
);
