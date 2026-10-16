// /api/createUser.js  — Vercel API Route
// Crea un usuario en Firebase Auth y guarda su perfil en Realtime Database
// Solo admins (Fede/Yeni) pueden llamar a este endpoint

import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getDatabase } from 'firebase-admin/database';

const ADMINS = ['m.fede.m@gmail.com', 'marketingroderichs@gmail.com'];

function initAdmin() {
  if (getApps().length > 0) return;
  initializeApp({
    credential: cert({
      projectId:   process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey:  process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    }),
    databaseURL: 'https://roderichevents-80dff-default-rtdb.firebaseio.com',
  });
}

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Method not allowed' });

  const { callerToken, email, password, nombre, rol, eventos } = req.body || {};

  if (!callerToken || !email || !password || !nombre) {
    return res.status(400).json({ ok: false, error: 'Faltan campos requeridos' });
  }

  try {
    initAdmin();
    const auth = getAuth();

    // Verificar que el caller es admin
    let callerEmail;
    try {
      const decoded = await auth.verifyIdToken(callerToken);
      callerEmail = decoded.email;
    } catch (e) {
      return res.status(401).json({ ok: false, error: 'Token inválido o expirado' });
    }

    if (!ADMINS.includes(callerEmail)) {
      return res.status(403).json({ ok: false, error: 'Sin permiso para crear usuarios' });
    }

    // Crear usuario en Firebase Auth
    const userRecord = await auth.createUser({
      email,
      password,
      displayName: nombre,
    });

    // Guardar perfil en Realtime Database
    const db = getDatabase();
    await db.ref(`re/usuarios/${userRecord.uid}`).set({
      uid:      userRecord.uid,
      email,
      nombre,
      rol:      rol || 'colaborador',
      eventos:  eventos || [],
      creadoPor: callerEmail,
      creadoEn: new Date().toISOString(),
    });

    return res.status(200).json({ ok: true, uid: userRecord.uid });

  } catch (err) {
    // Error de Firebase Auth (email ya existe, contraseña corta, etc.)
    const msg = err.code === 'auth/email-already-exists'
      ? 'Ya existe un usuario con ese email'
      : err.code === 'auth/invalid-password'
      ? 'La contraseña debe tener al menos 6 caracteres'
      : err.message;
    return res.status(500).json({ ok: false, error: msg });
  }
}
