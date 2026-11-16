'use strict'; // Habilita validaciones estrictas de JavaScript en este módulo.

const PDFDocument = require('pdfkit'); // Importa la librería que genera el documento en el servidor.

const COLORS = { // Define una paleta consistente para el informe.
    navy: '#10243A', // Usa azul oscuro para encabezados institucionales.
    blue: '#1D4ED8', // Usa azul vivo para acentos y títulos de secciones.
    ink: '#172033', // Usa un tono oscuro legible para el texto principal.
    muted: '#64748B', // Usa gris azulado para metadatos y textos secundarios.
    line: '#CBD5E1', // Usa gris claro para divisores y bordes de tabla.
    pale: '#EFF6FF', // Usa azul muy claro como fondo de bloques informativos.
    red: '#B91C1C', // Usa rojo para estados maliciosos.
    amber: '#B45309', // Usa ámbar para estados sospechosos.
    green: '#15803D', // Usa verde para estados seguros.
}; // Finaliza la paleta de colores.

function formatDate(value) { // Convierte fechas de MySQL a una cadena local legible.
    const date = value instanceof Date ? value : new Date(value); // Admite objetos Date y valores serializados.
    if (Number.isNaN(date.getTime())) return 'Fecha no disponible'; // Evita mostrar valores inválidos como fechas.
    return new Intl.DateTimeFormat('es-AR', { dateStyle: 'short', timeStyle: 'short' }).format(date); // Devuelve fecha y hora en español.
} // Finaliza el formateador de fechas.

function formatType(type) { // Convierte los tipos internos a etiquetas para lectores del informe.
    const labels = { url: 'URL', file: 'Archivo', email: 'Correo' }; // Declara las etiquetas permitidas.
    return labels[type] || 'Otro'; // Usa una etiqueta segura si llega un tipo inesperado.
} // Finaliza el formateador de tipos.

function formatStatus(status) { // Convierte los estados internos a etiquetas castellanas.
    const labels = { safe: 'Seguro', suspicious: 'Sospechoso', malicious: 'Malicioso' }; // Declara traducciones de estado.
    return labels[status] || 'Sin clasificar'; // Proporciona un valor legible para estados no reconocidos.
} // Finaliza el formateador de estados.

function statusColor(status) { // Selecciona el color del estado para su lectura rápida.
    const colors = { safe: COLORS.green, suspicious: COLORS.amber, malicious: COLORS.red }; // Asocia cada estado con un color.
    return colors[status] || COLORS.ink; // Usa el color principal como alternativa.
} // Finaliza la selección de color.

function addFooter(doc, pageNumber) { // Dibuja un pie de página discreto en la página actual.
    const y = doc.page.height - 38; // Ubica la línea cerca del borde inferior de la hoja.
    doc.save(); // Guarda el estado gráfico actual del documento.
    doc.strokeColor(COLORS.line).moveTo(48, y - 8).lineTo(doc.page.width - 48, y - 8).stroke(); // Dibuja un separador.
    doc.fontSize(8).fillColor(COLORS.muted).text('Cyberscan · Informe generado automáticamente', 48, y, { lineBreak: false }); // Añade la identificación del informe.
    doc.text(`Página ${pageNumber}`, doc.page.width - 100, y, { width: 52, align: 'right', lineBreak: false }); // Añade el número de página.
    doc.restore(); // Restaura estilos previos del documento.
} // Finaliza el pie de página.

function ensureSpace(doc, height, pageCounter) { // Crea una página si un bloque no cabe en el espacio restante.
    if (doc.y + height <= doc.page.height - 55) return pageCounter; // Conserva la página actual cuando queda espacio.
    addFooter(doc, pageCounter.value); // Completa el pie de página antes del salto.
    doc.addPage(); // Abre otra página del PDF.
    pageCounter.value += 1; // Mantiene actualizado el contador de páginas.
    drawRunningHeader(doc); // Repite el encabezado corto en páginas interiores.
    return pageCounter; // Devuelve el contador para facilitar su uso secuencial.
} // Finaliza la comprobación de espacio.

function drawRunningHeader(doc) { // Dibuja un encabezado compacto para las páginas posteriores.
    doc.save(); // Conserva el estilo del contenido que seguirá.
    doc.font('Helvetica-Bold').fontSize(9).fillColor(COLORS.navy).text('CYBERSCAN  /  INFORME DE AUDITORÍA', 48, 34, { lineBreak: false }); // Identifica el informe en páginas interiores.
    doc.strokeColor(COLORS.line).moveTo(48, 52).lineTo(doc.page.width - 48, 52).stroke(); // Separa el encabezado del contenido.
    doc.restore(); // Restaura el estado gráfico.
    doc.y = 68; // Coloca el cursor debajo del encabezado.
} // Finaliza el encabezado de páginas interiores.

function drawMetric(doc, x, y, width, label, value, note) { // Dibuja una tarjeta de resumen estadístico.
    doc.save(); // Aísla estilos de la tarjeta.
    doc.roundedRect(x, y, width, 69, 7).fillAndStroke(COLORS.pale, COLORS.line); // Dibuja una tarjeta con bordes suaves.
    doc.font('Helvetica').fontSize(8).fillColor(COLORS.muted).text(label.toUpperCase(), x + 10, y + 10, { width: width - 20 }); // Escribe el nombre de la métrica.
    doc.font('Helvetica-Bold').fontSize(19).fillColor(COLORS.navy).text(String(value), x + 10, y + 26, { width: width - 20 }); // Muestra el valor principal.
    doc.font('Helvetica').fontSize(7).fillColor(COLORS.muted).text(note, x + 10, y + 51, { width: width - 20 }); // Añade una descripción auxiliar.
    doc.restore(); // Restaura los estilos anteriores.
} // Finaliza la tarjeta estadística.

function buildAnalysisText(stats) { // Genera interpretación prudente basada únicamente en métricas agregadas.
    const maliciousPercent = stats.byStatus.malicious.percentage; // Lee la proporción clasificada como maliciosa.
    const suspiciousPercent = stats.byStatus.suspicious.percentage; // Lee la proporción clasificada como sospechosa.
    const exposurePercent = maliciousPercent + suspiciousPercent; // Calcula la exposición que requiere revisión.
    let level = 'baja'; // Asume una exposición baja para iniciar la clasificación.
    if (maliciousPercent >= 20 || exposurePercent >= 40) level = 'alta'; // Marca exposición alta cuando hay mayor concentración de señales.
    else if (exposurePercent >= 10) level = 'moderada'; // Marca exposición moderada si hay alertas relevantes.
    const intro = stats.total === 0 // Diferencia un conjunto sin datos de una muestra con actividad.
        ? 'No existen registros de análisis en la base de datos. No es posible estimar la exposición actual con este conjunto vacío.' // Evita inferencias sin observaciones.
        : `Se registraron ${stats.total} análisis. El ${exposurePercent.toFixed(2)}% fue clasificado como sospechoso o malicioso, por lo que la exposición observada se considera ${level}.`; // Resume la proporción observada.
    const recommendations = 'Recomendaciones: priorizar la revisión manual de los elementos maliciosos y sospechosos; aislar archivos señalados hasta confirmar su origen; validar reputación y certificados de URLs; y aplicar autenticación multifactor, actualización de sistemas y capacitación contra phishing. Los resultados dependen de la calidad y cobertura de los datos registrados y no sustituyen una auditoría técnica completa.'; // Añade mitigaciones sin afirmar más de lo que respaldan los datos.
    return `${intro}\n\n${recommendations}`; // Devuelve el análisis completo como texto fluido.
} // Finaliza el análisis automatizado.

function drawActivityRecord(doc, record, pageCounter) { // Representa un registro como una fila legible de la tabla de actividad.
    const left = 48; // Establece el margen izquierdo del registro.
    const contentWidth = doc.page.width - 96; // Calcula el ancho disponible entre márgenes.
    const detail = String(record.details || 'Sin detalle técnico informado.'); // Normaliza el detalle para evitar valores nulos.
    const target = String(record.target_value || 'Objetivo no informado.'); // Normaliza el objetivo.
    const firstLine = `${formatDate(record.created_at)}   ·   ${formatType(record.target_type)}   ·   ${formatStatus(record.status)}   ·   Riesgo ${record.risk_score}/100`; // Construye la línea superior de la entrada.
    const targetHeight = doc.heightOfString(target, { width: contentWidth - 12, font: 'Helvetica', fontSize: 8 }); // Mide objetivo con ajuste de línea.
    const detailHeight = doc.heightOfString(detail, { width: contentWidth - 12, font: 'Helvetica', fontSize: 8 }); // Mide detalle con ajuste de línea.
    const blockHeight = Math.max(54, 29 + targetHeight + detailHeight); // Reserva espacio para las tres líneas del registro.
    ensureSpace(doc, blockHeight + 8, pageCounter); // Evita que la entrada se corte entre páginas.
    const startY = doc.y; // Guarda la posición superior de la fila.
    doc.save(); // Aísla estilos del registro.
    doc.roundedRect(left, startY, contentWidth, blockHeight, 4).fillAndStroke('#FFFFFF', COLORS.line); // Dibuja el fondo y el borde de la fila.
    doc.font('Helvetica-Bold').fontSize(8).fillColor(statusColor(record.status)).text(firstLine, left + 8, startY + 7, { width: contentWidth - 16 }); // Destaca fecha, tipo, estado y riesgo.
    doc.font('Helvetica-Bold').fontSize(8).fillColor(COLORS.ink).text('Objetivo: ', left + 8, startY + 21, { continued: true }); // Introduce el valor analizado.
    doc.font('Helvetica').fontSize(8).fillColor(COLORS.ink).text(target, { width: contentWidth - 16 }); // Escribe el objetivo con ajuste automático.
    doc.font('Helvetica-Bold').fontSize(8).fillColor(COLORS.ink).text('Detalle: ', left + 8, doc.y + 3, { continued: true }); // Introduce el detalle técnico.
    doc.font('Helvetica').fontSize(8).fillColor(COLORS.ink).text(detail, { width: contentWidth - 16 }); // Escribe el detalle completo del hallazgo.
    doc.restore(); // Restaura los estilos globales.
    doc.y = startY + blockHeight + 7; // Sitúa el cursor debajo de la fila dibujada.
} // Finaliza el renderizado de un registro.

function generatePdf(doc, { stats, history }) { // Construye todas las páginas y secciones del reporte ejecutivo.
    const pageCounter = { value: 1 }; // Mantiene la numeración para los pies de página.
    const issuedAt = new Intl.DateTimeFormat('es-AR', { dateStyle: 'full', timeStyle: 'short' }).format(new Date()); // Captura fecha y hora de emisión.
    const pageWidth = doc.page.width; // Obtiene el ancho de la hoja actual.
    const cardGap = 10; // Define la separación horizontal entre tarjetas.
    const cardWidth = (pageWidth - 96 - cardGap * 2) / 3; // Calcula tarjetas de igual ancho dentro de los márgenes.
    const summary = buildAnalysisText(stats); // Prepara interpretación profesional de los resultados.

    doc.info.Title = 'Informe Ejecutivo de Auditoría y Análisis de Amenazas - Cyberscan'; // Establece metadatos del título PDF.
    doc.info.Author = 'Cyberscan'; // Establece metadatos del autor.
    doc.info.Subject = 'Resumen estadístico e historial de análisis de ciberseguridad'; // Describe el contenido del documento.
    doc.rect(0, 0, pageWidth, 162).fill(COLORS.navy); // Crea la banda institucional de portada.
    doc.font('Helvetica-Bold').fontSize(19).fillColor('#FFFFFF').text('Informe Ejecutivo de Auditoría', 48, 43, { width: pageWidth - 96 }); // Añade el encabezado formal principal.
    doc.font('Helvetica-Bold').fontSize(13).fillColor('#DBEAFE').text('y Análisis de Amenazas - Cyberscan', 48, 72, { width: pageWidth - 96 }); // Añade el nombre de la aplicación y alcance.
    doc.font('Helvetica').fontSize(9).fillColor('#E2E8F0').text(`Emitido: ${issuedAt}`, 48, 112); // Añade la fecha y hora de emisión.
    doc.font('Helvetica').fontSize(8).fillColor('#CBD5E1').text('Documento generado a partir de registros almacenados en MySQL.', 48, 130); // Indica el origen de la información.
    doc.y = 184; // Coloca el cursor después de la banda de portada.

    doc.font('Helvetica-Bold').fontSize(13).fillColor(COLORS.navy).text('Resumen estadístico'); // Añade el título de la primera sección.
    doc.moveDown(0.65); // Deja espacio entre el título y las tarjetas.
    const row1Y = doc.y; // Guarda la coordenada vertical de la primera fila.
    drawMetric(doc, 48, row1Y, cardWidth, 'Total de análisis', stats.total, 'Registros disponibles'); // Muestra cantidad de análisis.
    drawMetric(doc, 48 + cardWidth + cardGap, row1Y, cardWidth, 'Detección de amenazas', `${stats.threatDetectionRate.toFixed(2)}%`, 'Sospechosos + maliciosos'); // Muestra proporción de amenazas.
    drawMetric(doc, 48 + (cardWidth + cardGap) * 2, row1Y, cardWidth, 'Riesgo promedio', `${stats.averageRiskScore.toFixed(1)}/100`, 'Media del puntaje registrado'); // Muestra el riesgo promedio.
    doc.y = row1Y + 82; // Avanza debajo de las tarjetas de métricas generales.
    const row2Y = doc.y; // Guarda la coordenada vertical de la segunda fila.
    drawMetric(doc, 48, row2Y, cardWidth, 'URLs', stats.byType.url.count, `${stats.byType.url.percentage.toFixed(2)}% del total`); // Muestra la distribución de URLs.
    drawMetric(doc, 48 + cardWidth + cardGap, row2Y, cardWidth, 'Archivos', stats.byType.file.count, `${stats.byType.file.percentage.toFixed(2)}% del total`); // Muestra la distribución de archivos.
    drawMetric(doc, 48 + (cardWidth + cardGap) * 2, row2Y, cardWidth, 'Correos', stats.byType.email.count, `${stats.byType.email.percentage.toFixed(2)}% del total`); // Muestra la distribución de correos.
    doc.y = row2Y + 84; // Avanza debajo de las tarjetas por vector.

    const statusSummary = `Estados: ${stats.byStatus.safe.count} seguros (${stats.byStatus.safe.percentage.toFixed(2)}%), ${stats.byStatus.suspicious.count} sospechosos (${stats.byStatus.suspicious.percentage.toFixed(2)}%) y ${stats.byStatus.malicious.count} maliciosos (${stats.byStatus.malicious.percentage.toFixed(2)}%).`; // Construye el resumen por estado.
    doc.font('Helvetica').fontSize(9).fillColor(COLORS.ink).text(statusSummary, { width: pageWidth - 96 }); // Inserta el desglose de estados.
    doc.moveDown(1); // Separa el resumen estadístico del análisis.
    doc.font('Helvetica-Bold').fontSize(13).fillColor(COLORS.navy).text('Evaluación y recomendaciones'); // Introduce la interpretación profesional.
    doc.moveDown(0.4); // Deja espacio bajo el título.
    const analysisHeight = doc.heightOfString(summary, { width: pageWidth - 116, font: 'Helvetica', fontSize: 9, lineGap: 3 }); // Mide el bloque interpretativo.
    ensureSpace(doc, analysisHeight + 30, pageCounter); // Comprueba que la evaluación quepa en la página.
    const analysisY = doc.y; // Conserva la coordenada para dibujar el fondo del bloque.
    doc.roundedRect(48, analysisY - 5, pageWidth - 96, analysisHeight + 16, 5).fillAndStroke(COLORS.pale, COLORS.line); // Dibuja el bloque analítico.
    doc.font('Helvetica').fontSize(9).lineGap(3).fillColor(COLORS.ink).text(summary, 58, analysisY + 3, { width: pageWidth - 116 }); // Escribe interpretación y recomendaciones.
    doc.y = analysisY + analysisHeight + 23; // Avanza debajo del bloque.
    doc.moveDown(0.8); // Añade separación antes del historial.
    ensureSpace(doc, 38, pageCounter); // Reserva espacio para el título de actividad.
    doc.font('Helvetica-Bold').fontSize(13).fillColor(COLORS.navy).text('Detalle de actividad'); // Añade el título de la tabla de actividad.
    doc.moveDown(0.3); // Separa el título de los registros.

    if (history.length === 0) { // Trata explícitamente un historial vacío.
        doc.font('Helvetica').fontSize(9).fillColor(COLORS.muted).text('No hay elementos analizados registrados en la base de datos.', { width: pageWidth - 96 }); // Informa que no hay filas para presentar.
    } else { // Recorre el historial completo almacenado, sin descartar registros.
        history.forEach((record) => drawActivityRecord(doc, record, pageCounter)); // Añade cada registro con paginación automática.
    } // Finaliza la condición del historial vacío.

    addFooter(doc, pageCounter.value); // Dibuja el pie de página de la última página.
} // Finaliza la generación de contenido PDF.

module.exports = { PDFDocument, generatePdf }; // Expone el constructor y la función para el endpoint.