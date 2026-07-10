"use client";

import { useState } from "react";
import { supabase } from "@/lib/supabase";

export default function LoginForm() {

    const [email,setEmail]=useState("");
    const [password,setPassword]=useState("");

    async function login(){

        const {error}=await supabase.auth.signInWithPassword({

            email,

            password

        });

        if(error){

            alert(error.message);

            return;

        }

        window.location.href="/dashboard";

    }

    return(

        <div className="max-w-md mx-auto mt-20">

            <input

                className="w-full p-4 rounded-lg bg-slate-900"

                placeholder="Email"

                onChange={(e)=>setEmail(e.target.value)}

            />

            <input

                type="password"

                className="w-full p-4 rounded-lg bg-slate-900 mt-4"

                placeholder="Mot de passe"

                onChange={(e)=>setPassword(e.target.value)}

            />

            <button

                onClick={login}

                className="mt-6 w-full bg-cyan-500 text-black p-4 rounded-lg"

            >

                Connexion

            </button>

        </div>

    )

          }
