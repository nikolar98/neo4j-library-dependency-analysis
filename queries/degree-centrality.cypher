CALL gds.graph.project(
'libraryGraph',
'Library',
'DEPENDS_ON'
);

CALL gds.degree.stream('libraryGraph')
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).name AS library, score
ORDER BY score DESC
LIMIT 10;

CALL gds.degree.stream('libraryGraph')
YIELD nodeId, score
WITH gds.util.asNode(nodeId) AS node, score
WHERE node.vulnerabilityCount > 0
RETURN node.name, score, node.maxSeverity
ORDER BY score DESC
LIMIT 5;
