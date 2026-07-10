import Link from "next/link";


export default function Home(){


return (

<main className="min-h-screen flex items-center justify-center">


<div className="text-center">


<h1 className="
text-6xl
font-bold
bg-gradient-to-r
from-cyan-400
to-purple-500
bg-clip-text
text-transparent
">

AegisAI

</h1>


<p className="mt-6 text-gray-300 text-xl">

Plateforme intelligente d'analyse de sécurité web

</p>


<Link

href="/dashboard"

className="
inline-block
mt-10
px-8
py-4
rounded-xl
bg-cyan-500
text-black
font-bold
hover:scale-105
transition
"

>

Accéder au dashboard

</Link>


</div>


</main>

)

}
