// Page d'essai de la porte (lot 2, étape 2a) : capturer une vraie lettre d'enregistrement et une vraie lettre de
// signature d'un iPhone. RP ID d'essai : la clé créée ici ne vaut que pour essai.porte.labo.bluedigitalworks.com.
// Rien ne part sur le réseau : le résultat s'affiche, on le copie, on le colle dans un fichier sur le Mac.
"use strict";

const RP_ID = "essai.porte.labo.bluedigitalworks.com";
const $ = (id) => document.getElementById(id);

// base64url sans « = », dans les deux sens
function versB64url(octets) {
  let s = "";
  for (const o of new Uint8Array(octets)) s += String.fromCharCode(o);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function depuisB64url(texte) {
  const s = atob(texte.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((texte.length + 3) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}
function aleatoire(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// Le défi de la signature : celui du lien (#<numéro>.<code>.<défi>, comme la vraie porte), sinon un défi au hasard.
function defiDuLien() {
  const m = /^#(\d{1,9})\.([0-9A-F]{4}-[0-9A-F]{4})\.([A-Za-z0-9_-]{43})$/.exec(location.hash);
  return m ? { numero: m[1], code: m[2], defi: m[3] } : null;
}

function montrer(message, objet) {
  $("message").textContent = message;
  $("sortie").value = objet ? JSON.stringify(objet, null, 2) : "";
}

function contexte() {
  return { page: location.origin + location.pathname, lien: location.hash || null, navigateur: navigator.userAgent,
           quand: new Date().toISOString() };
}

async function verifierNavigateur() {
  if (!window.PublicKeyCredential) {
    $("etat").textContent = "✘ Ce navigateur ne sait pas faire Face ID pour une page web. Touche ⋯ puis « Ouvrir dans Safari ».";
    return;
  }
  let plateforme = "inconnu";
  try {
    plateforme = (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) ? "oui" : "non";
  } catch (e) { plateforme = "erreur : " + e.name; }
  const lien = defiDuLien();
  $("etat").textContent = "✔ Ce navigateur sait faire les clés (Face ID disponible : " + plateforme + ")."
    + (lien ? " Lien de question n°" + lien.numero + ", code " + lien.code + "." : "");
}

async function creer() {
  const defi = aleatoire(32);
  try {
    const c = await navigator.credentials.create({ publicKey: {
      rp: { id: RP_ID, name: "Porte (essai)" },
      user: { id: aleatoire(16), name: "essai", displayName: "Essai de la porte" },
      challenge: defi,
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],          // ES256 seul
      authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required",
                                userVerification: "required" },
      attestation: "none",
      timeout: 120000,
    } });
    montrer("✔ Clé d'essai créée. Copie le résultat et colle-le sur le Mac.", {
      genre: "enregistrement", ...contexte(), defi: versB64url(defi),
      id: c.id, rawId: versB64url(c.rawId), type: c.type,
      authenticatorAttachment: c.authenticatorAttachment || null,
      transports: c.response.getTransports ? c.response.getTransports() : null,
      clientDataJSON: versB64url(c.response.clientDataJSON),
      attestationObject: versB64url(c.response.attestationObject),
      extensions: c.getClientExtensionResults(),
    });
  } catch (e) {
    montrer("✘ Rien n'a été créé (" + e.name + ") : " + e.message, { genre: "erreur-enregistrement", ...contexte(),
                                                                      erreur: e.name, detail: e.message });
  }
}

async function signer() {
  const lien = defiDuLien();
  const defi = lien ? depuisB64url(lien.defi) : aleatoire(32);     // 43 signes → 32 octets, comme la vraie porte
  try {
    const a = await navigator.credentials.get({ publicKey: {
      rpId: RP_ID, challenge: defi, userVerification: "required", timeout: 120000,
    } });
    montrer("✔ Signé. Copie le résultat et colle-le sur le Mac.", {
      genre: "signature", ...contexte(), defi: versB64url(defi),
      id: a.id, rawId: versB64url(a.rawId), type: a.type,
      authenticatorAttachment: a.authenticatorAttachment || null,
      clientDataJSON: versB64url(a.response.clientDataJSON),
      authenticatorData: versB64url(a.response.authenticatorData),
      signature: versB64url(a.response.signature),
      userHandle: a.response.userHandle ? versB64url(a.response.userHandle) : null,
      extensions: a.getClientExtensionResults(),
    });
  } catch (e) {
    montrer("✘ Rien n'a été signé (" + e.name + ") : " + e.message, { genre: "erreur-signature", ...contexte(),
                                                                       erreur: e.name, detail: e.message });
  }
}

async function copier() {
  const t = $("sortie").value;
  if (!t) return;
  try {
    await navigator.clipboard.writeText(t);
    $("message").textContent = "✔ Copié. Colle-le dans un fichier sur le Mac.";
  } catch (e) {
    $("sortie").select();                                          // repli : le texte est sélectionné, à copier à la main
    $("message").textContent = "Copie automatique impossible : le texte est sélectionné, touche « Copier ».";
  }
}

$("creer").addEventListener("click", creer);
$("signer").addEventListener("click", signer);
$("copier").addEventListener("click", copier);
verifierNavigateur();
