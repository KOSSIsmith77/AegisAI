"use client";

import { useState } from "react";
import { supabase } from "@/lib/supabase";

export default function RegisterForm(){

    const [email,setEmail]=useState("");
    const [password,setPassword]=useState("");

    async function register(){

        const {error}=await supabase.auth.signUp({

            email,

            password

        });

        if(error){

            alert(error.message);

            return;

        }

        alert("Compte créé. Vérifie ton email.");

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

                onClick={register}

                className="w-full bg-purple-500 p-4 rounded-lg mt-5"

            >

                Créer un compte

            </button>

        </div>

    )

          }
