// Le code commun aux deux pages de la porte (portes, lot 2c) : base64url, et l'EMPREINTE de la clé, calculée EXACTEMENT
// comme le Mac (`atelier/porte_webauthn.empreinte`) : sha256 de la clé publique SPKI lue dans authData, 80 bits, 16 signes
// base32 en 4 groupes. Une seule forme acceptée, celle qu'émet l'iPhone (capturée en 2a) ; toute autre = refus.
"use strict";
(function () {
  function hex(h) {
    return Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
  }
  const ATTESTATION_TETE = hex("a363666d74646e6f6e656761747453746d74a068617574684461746158");
  const COSE_X = hex("a5010203262001215820");
  const COSE_Y = hex("225820");
  const SPKI_P256 = hex("3059301306072a8648ce3d020106082a8648ce3d030107034200");
  const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  function versB64url(octets) {
    let s = "";
    for (const o of new Uint8Array(octets)) s += String.fromCharCode(o);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function depuisB64url(texte) {
    if (typeof texte !== "string" || !/^[A-Za-z0-9_-]*$/.test(texte) || texte.length % 4 === 1) {
      throw new Error("base64url illisible");
    }
    const s = atob(texte.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((texte.length + 3) % 4));
    return Uint8Array.from(s, (c) => c.charCodeAt(0));
  }

  function commencePar(octets, tete) {
    return octets.length >= tete.length && tete.every((o, i) => octets[i] === o);
  }

  function base32(octets) {                        // RFC 4648, sans remplissage : 10 octets = 16 signes exactement
    let bits = 0, valeur = 0, sortie = "";
    for (const o of octets) {
      valeur = (valeur << 8) | o;
      bits += 8;
      while (bits >= 5) {
        sortie += BASE32[(valeur >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) sortie += BASE32[(valeur << (5 - bits)) & 31];
    return sortie;
  }

  async function empreinteDepuisAttestation(attestationB64) {
    const ao = depuisB64url(attestationB64);
    if (!commencePar(ao, ATTESTATION_TETE) || ao.length < ATTESTATION_TETE.length + 1) {
      throw new Error("objet d'attestation d'une autre forme");
    }
    const n = ao[ATTESTATION_TETE.length];
    const auth = ao.slice(ATTESTATION_TETE.length + 1);
    if (auth.length !== n || auth.length < 55) throw new Error("authData incohérent");
    const longueur = (auth[53] << 8) | auth[54];
    if (longueur < 16 || longueur > 1023) throw new Error("identifiant de clé impossible");
    const cose = auth.slice(55 + longueur);
    if (cose.length !== 77 || !commencePar(cose, COSE_X) || !commencePar(cose.slice(42), COSE_Y)) {
      throw new Error("clé d'une autre forme que ES256");
    }
    const spki = new Uint8Array(SPKI_P256.length + 65);
    spki.set(SPKI_P256, 0);
    spki[SPKI_P256.length] = 4;
    spki.set(cose.slice(10, 42), SPKI_P256.length + 1);
    spki.set(cose.slice(45, 77), SPKI_P256.length + 33);
    const h = new Uint8Array(await crypto.subtle.digest("SHA-256", spki)).slice(0, 10);
    return base32(h).match(/.{4}/g).join("-");
  }

  globalThis.PorteCommun = { versB64url, depuisB64url, empreinteDepuisAttestation };
})();
