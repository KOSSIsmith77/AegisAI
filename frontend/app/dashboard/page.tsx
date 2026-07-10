import Sidebar from "@/components/Sidebar";
import StatCard from "@/components/StatCard";

export default function Dashboard() {

    return (

        <div className="flex">

            <Sidebar />

            <main className="flex-1 p-10">

                <h1 className="text-4xl font-bold">

                    Dashboard

                </h1>

                <div className="grid md:grid-cols-4 gap-6 mt-10">

                    <StatCard
                        title="Score"
                        value="92"
                        color="text-green-400"
                    />

                    <StatCard
                        title="Scans"
                        value="124"
                        color="text-cyan-400"
                    />

                    <StatCard
                        title="Vulnérabilités"
                        value="31"
                        color="text-red-400"
                    />

                    <StatCard
                        title="Plan"
                        value="FREE"
                        color="text-yellow-400"
                    />

                </div>

            </main>

        </div>

    );

}
