"use client";

import Link from "next/link";
import {
    LayoutDashboard,
    Shield,
    History,
    MessageSquare,
    CreditCard,
    Settings
} from "lucide-react";

const menu = [
    {
        title: "Dashboard",
        href: "/dashboard",
        icon: LayoutDashboard
    },
    {
        title: "Scanner",
        href: "/scanner",
        icon: Shield
    },
    {
        title: "Historique",
        href: "/history",
        icon: History
    },
    {
        title: "Assistant IA",
        href: "/assistant",
        icon: MessageSquare
    },
    {
        title: "Abonnement",
        href: "/pricing",
        icon: CreditCard
    },
    {
        title: "Paramètres",
        href: "/settings",
        icon: Settings
    }
];

export default function Sidebar() {

    return (

        <aside className="w-64 bg-slate-950 min-h-screen border-r border-slate-800">

            <div className="p-6">

                <h1 className="text-3xl font-bold text-cyan-400">

                    AegisAI

                </h1>

            </div>

            <nav>

                {

                    menu.map(item => {

                        const Icon = item.icon;

                        return (

                            <Link
                                key={item.href}
                                href={item.href}
                                className="flex items-center gap-4 px-6 py-4 hover:bg-slate-900 transition"
                            >

                                <Icon size={20} />

                                {item.title}

                            </Link>

                        );

                    })

                }

            </nav>

        </aside>

    )

}
