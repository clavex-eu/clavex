package eu.clavex.cibademo

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.EuroSymbol
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CibaApprovalSheet(
    request: CibaRequest,
    onDismiss: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var isLoading by remember { mutableStateOf(false) }
    var finished by remember { mutableStateOf(false) }
    var wasApproved by remember { mutableStateOf(false) }

    ModalBottomSheet(onDismissRequest = onDismiss) {
        if (finished) {
            // Result screen
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 32.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Icon(
                    imageVector = if (wasApproved) Icons.Outlined.EuroSymbol else Icons.Outlined.EuroSymbol,
                    contentDescription = null,
                    modifier = Modifier.size(56.dp),
                    tint = if (wasApproved) MaterialTheme.colorScheme.primary
                           else MaterialTheme.colorScheme.error,
                )
                Text(
                    if (wasApproved) "Payment Approved" else "Payment Denied",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )
                TextButton(onClick = onDismiss) { Text("Close") }
                Spacer(Modifier.height(16.dp))
            }
        } else {
            // Approval screen
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp)
                    .padding(bottom = 32.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(20.dp),
            ) {
                Text(
                    "Payment Request",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                )

                // EBA SCA requirement: binding_message must be prominently shown
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant,
                    ),
                ) {
                    Text(
                        text = request.bindingMessage,
                        modifier = Modifier.padding(16.dp).fillMaxWidth(),
                        style = MaterialTheme.typography.bodyLarge,
                        textAlign = TextAlign.Center,
                    )
                }

                Text(
                    "Expires in ${request.expiresIn}s",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.outline,
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                isLoading = true
                                ClavexRepository.postDecision(request.denyUrl)
                                wasApproved = false
                                finished = true
                                isLoading = false
                            }
                        },
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading,
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.error,
                        ),
                    ) { Text("Deny") }

                    Button(
                        onClick = {
                            scope.launch {
                                isLoading = true
                                ClavexRepository.postDecision(request.approveUrl)
                                wasApproved = true
                                finished = true
                                isLoading = false
                            }
                        },
                        modifier = Modifier.weight(1f),
                        enabled = !isLoading,
                    ) {
                        if (isLoading) {
                            CircularProgressIndicator(
                                Modifier.size(18.dp),
                                color = MaterialTheme.colorScheme.onPrimary,
                                strokeWidth = 2.dp,
                            )
                        } else {
                            Text("Approve")
                        }
                    }
                }
            }
        }
    }
}
