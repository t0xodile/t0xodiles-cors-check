import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import burp.api.montoya.utilities.json.JsonNode
import com.google.common.net.InternetDomainName
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadPoolExecutor
import javax.swing.*
import kotlin.concurrent.thread


class CustomContextMenuItemsProvider(private val api: MontoyaApi, private val threadPool: ThreadPoolExecutor) : ContextMenuItemsProvider {
    private var externalSubDomainLookup = false
    override fun provideMenuItems(event: ContextMenuEvent): MutableList<JMenuItem> {
        val menuItemList = ArrayList<JMenuItem>()

        val findSubdomains = JMenuItem("Open trusted domains scanner")

        //Target host of selected request
        val selectedRequest = event.messageEditorRequestResponse().get().requestResponse().request()

        //
        findSubdomains.addActionListener {
            SwingUtilities.invokeLater{
                openNewWindow(selectedRequest)
            }
        }
        menuItemList.add(findSubdomains)
        return menuItemList
    }

    private fun openNewWindow(selectedRequest: HttpRequest) {
        SwingUtilities.invokeLater {
            val frame = JFrame("Trusted Domain Scan Config")
            frame.defaultCloseOperation = JFrame.DISPOSE_ON_CLOSE
            frame.setSize(600, 400)
            frame.layout = BorderLayout()

            // Center the window on the screen
            frame.setLocationRelativeTo(null)

            // Create a panel to hold both the checkbox and text area
            val mainPanel = JPanel()
            mainPanel.layout = BoxLayout(mainPanel, BoxLayout.Y_AXIS)

            // Add a descriptive label to explain the text box
            val descriptionText = JTextArea(
                """Enter the list of domains that may be trusted by the target endpoint (one per line).""".trimMargin()
            )
            descriptionText.isEditable = false  // Make it non-editable like a label
            descriptionText.wrapStyleWord = true  // Enable word wrapping
            descriptionText.lineWrap = true
            descriptionText.isOpaque = false  // Make background transparent like a label
            //descriptionText.border = null  // Remove border for a clean label-like appearance
            descriptionText.font = descriptionText.font.deriveFont(14f)  // Adjust font size if needed
            descriptionText.isFocusable = false //Prevent the cursor appearing on it...

            // Add the description text to the panel
            mainPanel.add(descriptionText)

            // Create the checkbox for external subdomain lookup
            val externalLookupCheckBox = JCheckBox("Enable external subdomain lookup")
            externalLookupCheckBox.isSelected = false  // Off by default

            // Add a tooltip to the checkbox
            externalLookupCheckBox.toolTipText = "WARNING: When enabled, leaks the domains included in the list below to 'https://ip.thc.org/docs/API/subdomain-lookup'."


            // Initialize externalSubDomainLookup based on the initial state of the checkbox
            externalSubDomainLookup = externalLookupCheckBox.isSelected

            // Add an action listener to update the externalSubDomainLookup variable
            externalLookupCheckBox.addActionListener {
                externalSubDomainLookup = externalLookupCheckBox.isSelected
            }

            // Add a horizontal separator (JSeparator)
            val separator = JSeparator(SwingConstants.HORIZONTAL)
            separator.maximumSize = Dimension(600, 10)  // Adjust the width and height of the separator if needed
            mainPanel.add(separator)

            // Create a panel for the button and center-align it
            val checkBoxPanel = JPanel()
            checkBoxPanel.layout = BoxLayout(checkBoxPanel, BoxLayout.X_AXIS)
            checkBoxPanel.alignmentX = Component.CENTER_ALIGNMENT  // Center the button

            // Add the checkbox to the checkbox panel
            checkBoxPanel.add(externalLookupCheckBox)  // Add the checkbox to the main panel
            mainPanel.add(checkBoxPanel)

            // Create a text area for editable text input
            val textArea = JTextArea(selectedRequest.httpService().host())
            textArea.lineWrap = true
            textArea.wrapStyleWord = true
            textArea.isEditable = true
            textArea.isFocusable = true

            // Add the text area to a scroll pane in case of long content
            val scrollPane = JScrollPane(textArea)
            scrollPane.preferredSize = Dimension(580, 320)
            mainPanel.add(scrollPane)

            // Create a panel for the button and center-align it
            val buttonPanel = JPanel()
            buttonPanel.layout = BoxLayout(buttonPanel, BoxLayout.X_AXIS)
            buttonPanel.alignmentX = Component.CENTER_ALIGNMENT  // Center the button

            // Create the "Run trusted domain scan" button
            val runButton = JButton("Run trusted domain scan")
            runButton.preferredSize = Dimension(200, 40)
            runButton.toolTipText = "Finds trusted domains, then checks each trusted domain for Permissive CORS issues."

            runButton.addActionListener {
                // Close the window when the button is clicked
                frame.dispose()
                //Run in thread to prevent UI from hanging....
                thread {
                    // Run the scan, but only if there isn't arbitrary origin reflection. Otherwise no point!
                    if (!checkArbitraryOriginReflection(api, selectedRequest, threadPool)) {
                        runTrustedDomainScan(textArea.text, selectedRequest)
                    }
                }
            }

            buttonPanel.add(runButton)
            mainPanel.add(buttonPanel)  // Add the button panel to the main panel

            // Add the main panel to the frame
            frame.add(mainPanel, BorderLayout.CENTER)

            // Show the window
            frame.isVisible = true
        }
    }

    // Runs the scan for trusted domains based on user input
    private fun runTrustedDomainScan(domainsText: String, selectedRequest: HttpRequest) {
        // Split the text area content by newlines to get the list of domains
        val parentDomains: MutableList<String> = domainsText.split("\n").map { it.trim() }.filter { it.isNotEmpty() }.toMutableList()

        // Add other possible trusted domains
        parentDomains.addAll(defaultTrustedDomains)

        val allDomains = mutableMapOf<String, MutableList<String>>()

        // Set up the countdown latch to wait for all subdomain lookups to finish
        val latch = CountDownLatch(parentDomains.size)

        for (domain in parentDomains) {
            // Don't do stuff if we're unloaded
            if (CorsCheckExtension.unloaded) {
                break
            }

            // Don't do lookups for things like "localhost"
            if (domain in defaultTrustedDomains) {
                latch.countDown() // Decrement because we are "finishing" with this item
                continue
            }

            thread {
                try {
                    //Create a list of subdomains for this specific parent domain
                    val subDomainsForParent = mutableListOf<String>()

                    val topPrivateDomain = InternetDomainName.from(domain).topPrivateDomain().toString()

                    //Add the OG parent domain in case it trusts itself!
                    subDomainsForParent.add(domain.removeSuffix(".$topPrivateDomain"))

                    //Check if enabled
                    if (externalSubDomainLookup) {

                        api.logging().logToOutput("Looking up subdomains for: $topPrivateDomain")
                        val url = "https://ip.thc.org/api/v1/lookup/subdomains"

                        val apiResp = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url)
                            .withMethod("POST")
                            .withHeader("Content-Type", "application/json")
                            .withBody("{\"domain\":\"$topPrivateDomain\",\"limit\":0}")
                        )


                        //Only add remaining domains to list if we get a successful response!
                        if (apiResp.response().statusCode().toInt() == 200) {
                            if (api.utilities().jsonUtils().read(apiResp.response().bodyToString(), "matching_records").toInt() != 0) {
                                val domains = api.utilities().jsonUtils().read(apiResp.response().bodyToString(), "domains")
                                val something = JsonNode.jsonNode(domains)

                                val array = something.asArray()

                                for (test in array.asList()) {
                                    subDomainsForParent.add(api.utilities().jsonUtils().read(test.toJsonString(), "domain").replace("\"", "").removeSuffix(".$topPrivateDomain"));
                                }

                            } else {
                                api.logging().logToOutput("No subdomains found for $topPrivateDomain")
                            }
                        }
                    }

                    //Add the list of subdomains to the map with the parent domain as they key
                    synchronized(allDomains) {
                        allDomains.getOrPut(topPrivateDomain) { mutableListOf() }.addAll(subDomainsForParent)
                    }

                } catch (e: Exception) {
                    api.logging().logToError("Error looking up $domain: ${e.message}")
                } finally {
                    // Decrement the latch count when the thread finishes
                    latch.countDown()
                }
            }
        }

        // Wait for all threads to finish before continuing
        latch.await()

        // Log the selected domain
        api.logging().logToOutput("\r\nSelected domain for CORS checks: ${selectedRequest.httpService()}")

        // Send the selected domain and subdomains for CORS check
        TrustedDomainCheck.runTrustedDomainCheck(api, allDomains, selectedRequest)
    }
}