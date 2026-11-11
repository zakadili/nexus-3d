export function shortestPath(graph,source,target,disabled=[]){
 const nodes=new Set(graph.nodes.map(n=>n.id));
 if(!nodes.has(source)||!nodes.has(target))throw Error('Unknown graph node');
 const blocked=new Set(disabled),queue=[[source]],seen=new Set([source]);
 while(queue.length){const path=queue.shift(),last=path.at(-1);if(last===target)return path;
 for(const edge of graph.edges)if(edge.source===last&&!blocked.has(edge.source+'->'+edge.target)&&!seen.has(edge.target)){seen.add(edge.target);queue.push([...path,edge.target])}}
 return [];
}
