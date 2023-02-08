"use strict";

import fp from "fastify-plugin";
import { createHash } from "crypto";
import fnv1a from "./fnv1a.js";
import murmur2 from "./murmur2.js";
import murmur3 from "./murmur3.js";
import crc32 from "crc-32";
import MurmurHash3 from "murmurhash3js-revisited";
import murmur3HashWasm from "murmur3hash-wasm";

function djb2(input) {
  let hash = 0;
  let i = 0;
  const il = input.length;
  for (i = 0; i < il; ++i) {
    hash = ((hash << 5) - hash + input[i]) & 0xffffffff;
  }

  return hash >>> 0;
}

function validateAlgorithm(algorithm) {
  if (algorithm === "fnv1a") {
    return true;
  }

  // validate that the algorithm is supported by the node runtime
  try {
    createHash(algorithm);
  } catch (e) {
    throw new TypeError(`Algorithm ${algorithm} not supported.`);
  }
}

const lookup = {
  crc32: (key) => crc32.str(key),
  crc32b: (key) => crc32.buf(key),
  djb2,
  fnv1a,
  murmur2: (key) => murmur2(key, 0),
  murmur3: (key) => murmur3(key, 0),
  MurmurHash3: (key) => MurmurHash3.x86.hash32(key),
  murmur3HashWasm: (key) => murmur3HashWasm(key, 0),
};

function buildHashFn(algorithm = "fnv1a", weak = false) {
  const prefix = weak ? 'W/"' : '"';
  if (lookup[algorithm] !== undefined)
    return (payload) => prefix + lookup[algorithm](payload).toString(36) + '"';

  return (payload) =>
    prefix +
    createHash(algorithm).update(payload).digest().toString("base64") +
    '"';
}

async function fastifyEtag(app, opts) {
  const hash = buildHashFn(opts.algorithm, opts.weak);

  app.addHook("onSend", function (req, reply, payload, done) {
    let etag = reply.getHeader("etag");
    let newPayload;

    // we do not generate with an already existing etag
    if (!etag) {
      // we do not generate etags for anything but strings and buffers
      if (!(typeof payload === "string" || payload instanceof Buffer)) {
        done(null, newPayload);
        return;
      }

      etag = hash(payload);
      reply.header("etag", etag);
    }

    if (req.headers["if-none-match"] === etag) {
      reply.code(304);
      newPayload = "";
    }
    done(null, newPayload);
  });
}

const fastifyEtagPlugin = fp(fastifyEtag, {
  fastify: "4.x",
  name: "@fastify/etag",
});
export default fastifyEtagPlugin;
