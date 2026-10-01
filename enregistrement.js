// La page d'ENREGISTREMENT de la passkey de la porte (portes, lot 2c, option B) : servie HORS du serveur de la porte
// (GitHub Pages, sous-domaine « enregistrement. » du nom de la porte), pour qu'un serveur piraté ne puisse pas la
// remplacer. Elle crée la passkey (identifiant = le nom de la porte), affiche l'EMPREINTE de la clé (16 signes, calculée
// ici, sur ce téléphone, exactement comme le Mac) et poste la lettre à la boîte aux lettres de la porte, en lisant la
// réponse (la boîte l'autorise pour cette seule page) : un refus (boîte saturée) se dit, au lieu d'un « envoyée »
// trompeur. Le Mac fait taper ces 16 signes au Terminal : c'est la seule barrière contre une clé échangée en route.
"use strict";
(function () {
  const M = {
    navigateur: "Ce navigateur ne sait pas faire Face ID. Dans Telegram : Réglages → Privacy and Security → Open Links in → Safari, puis touche de nouveau le lien. (En dépannage : ⋯ → Ouvrir dans Safari.)",
    annule: "Rien n'a été envoyé. Tu peux réessayer, ou appuyer sur ✖ Stop dans Porte.",
    envoye: "La clé est envoyée. Tape les 16 signes au Terminal ; la confirmation arrivera dans Porte.",
    lien: "Ce lien d'enregistrement est incomplet ou a expiré : relance l'enregistrement au Terminal.",
    sature: "La boîte aux lettres de la porte est saturée en ce moment : la clé n'est pas arrivée. Attends un peu, puis relance l'enregistrement au Terminal.",
    incertain: "Je ne sais pas si la clé est arrivée. Si le Terminal te demande les 16 signes, les voici ; sinon, relance l'enregistrement au Terminal.",
  };
  const SATUREE = [429, 503, 507];
  const PREFIXE = "enregistrement.";
  const $ = (id) => document.getElementById(id);
  const bouton = $("enregistrer");
  const dire = (texte) => { $("message").textContent = texte; };
  const fermer = (texte) => { bouton.disabled = true; $("consigne").hidden = true; dire(texte); };

  const m = /^#([A-Za-z0-9_-]{43})$/.exec(location.hash);
  const rp = location.hostname.startsWith(PREFIXE) ? location.hostname.slice(PREFIXE.length) : null;
  if (window.top !== window.self || !m || !rp) return fermer(M.lien);
  if (!window.PublicKeyCredential || !navigator.credentials) return fermer(M.navigateur);
  const defi = m[1];

  bouton.addEventListener("click", async () => {
    bouton.disabled = true;
    dire("");
    let c;
    try {
      c = await navigator.credentials.create({ publicKey: {
        rp: { id: rp, name: "Porte" },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "proprietaire", displayName: "Porte" },
        challenge: PorteCommun.depuisB64url(defi),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { authenticatorAttachment: "platform", residentKey: "required", userVerification: "required" },
        attestation: "none",
        timeout: 120000,
      } });
    } catch (e) {
      dire(e && e.name === "NotAllowedError" ? [M.annule, M.navigateur].join("\n\n") : M.annule);
      bouton.disabled = false;
      return;
    }
    const attestation = PorteCommun.versB64url(c.response.attestationObject);
    let empreinte;
    try {
      empreinte = await PorteCommun.empreinteDepuisAttestation(attestation);
    } catch (e) {
      return fermer(M.annule);
    }
    const lettre = {
      rawId: PorteCommun.versB64url(c.rawId),
      clientDataJSON: PorteCommun.versB64url(c.response.clientDataJSON),
      attestationObject: attestation,
      transports: c.response.getTransports ? c.response.getTransports() : [],
    };
    const montrer = (texte) => {
      $("consigne").hidden = true;
      $("empreinte").textContent = empreinte;
      $("cellule").hidden = false;
      dire(texte);
    };
    let r;
    try {
      r = await fetch("https://" + rp + "/enregistrement", { method: "POST", mode: "cors",
        headers: { "Content-Type": "text/plain;charset=UTF-8" }, body: JSON.stringify(lettre),
        credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer" });
    } catch (e) {
      return montrer(M.incertain);            // réponse illisible : la lettre est peut-être arrivée, les 16 signes servent
    }
    if (r.status === 204) return montrer(M.envoye);
    bouton.disabled = false;
    dire(SATUREE.includes(r.status) ? M.sature : M.annule);
  });
})();
