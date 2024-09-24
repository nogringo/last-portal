/* eslint-disable object-curly-spacing */

const { onRequest } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const { Timestamp } = require("firebase-admin/firestore");
const speakeasy = require("speakeasy");

admin.initializeApp();

const db = admin.firestore();

exports.createPortal = onRequest(async (req, res) => {
  const importantData = req.body.importantData;
  if (typeof importantData !== "string") {
    res.json({
      success: false,
      message: "Invalid field: 'importantData' must be a string",
    });
    return;
  }

  const openIn = req.body.openIn || 400;
  if (typeof openIn !== "number" || openIn <= 0) {
    return res.json({
      success: false,
      message: "Invalid field: 'openIn' must be a positive number",
    });
  }

  const mainSecret = speakeasy.generateSecret().base32;
  const openSecret = speakeasy.generateSecret().base32;

  const portalData = {
    importantData,
    lastActivity: Timestamp.now(),
    mainSecret,
    openSecret,
  };

  if (openIn !== undefined) {
    portalData.openIn = openIn;
  }

  const docRef = await db.collection("portals").add(portalData);

  res.json({
    success: true,
    data: {
      portalId: docRef.id,
      mainSecret,
      openSecret,
    },
    message: "Portal successfully created",
  });
  return;
});

exports.resetPortal = onRequest(async (req, res) => {
  const portalId = req.body.portalId;
  if (typeof portalId !== "string") {
    res.json({
      success: false,
      message: "Invalid field: 'portalId' must be a string",
    });
    return;
  }

  const token = req.body.token;
  if (typeof token !== "string") {
    res.json({
      success: false,
      message: "Invalid field: 'token' must be a string",
    });
    return;
  }

  const docRef = db.collection("portals").doc(portalId);
  const portal = await docRef.get();
  if (!portal.exists) {
    return res.json({
      success: false,
      message: "Portal not found",
    });
  }
  const portalData = portal.data();

  const isValid = speakeasy.totp.verify({
    secret: portalData.mainSecret,
    encoding: "base32",
    token: token,
    window: 1,
  });

  if (!isValid) {
    res.json({
      success: false,
      message: "Invalid token",
    });
    return;
  }

  await docRef.update({
    lastActivity: Timestamp.now(),
  });

  res.json({
    success: true,
    message: "Portal successfully reset",
  });
  return;
});

exports.openPortal = onRequest(async (req, res) => {
  const portalId = req.body.portalId;
  if (typeof portalId !== "string") {
    res.json({
      success: false,
      message: "Invalid field: 'portalId' must be a string",
    });
    return;
  }

  const token = req.body.token;
  if (typeof token !== "string") {
    res.json({
      success: false,
      message: "Invalid field: 'token' must be a string",
    });
    return;
  }

  const docRef = db.collection("portals").doc(portalId);
  const portal = await docRef.get();
  if (!portal.exists) {
    return res.json({
      success: false,
      message: "Portal not found",
    });
  }
  const portalData = portal.data();

  const isValid = speakeasy.totp.verify({
    secret: portalData.openSecret,
    encoding: "base32",
    token: token,
    window: 1,
  });

  if (!isValid) {
    res.json({
      success: false,
      message: "Invalid token",
    });
    return;
  }

  const millisecondsInADay = 24 * 60 * 60 * 1000;
  const millisecondsToOpen = portalData.openIn * millisecondsInADay;
  const openDate = portalData.lastActivity.toMillis() + millisecondsToOpen;
  const isOpen = Date.now() > openDate;
  if (!isOpen) {
    res.json({
      success: false,
      data: openDate,
      message: "The portal is still closed",
    });
    return;
  }

  res.json({
    success: isValid,
    data: {
      importantData: portalData.importantData,
    },
    message: "Portal successfully opened",
  });
  return;
});
