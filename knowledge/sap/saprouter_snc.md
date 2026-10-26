# SAProuter route permissions and SNC

SAP Help: https://help.sap.com/docs/SAP_NETWEAVER_700/10977ac76c531014a966b3f130d4f853/658d09ab5c7e46028f633bb01a09b380.html

SAP documents route permission entries for ordinary and SNC-protected routes. Rule order matters: the first matching entry is applied. A broad normal permission before a more specific SNC rule can prevent that SNC rule from enforcing the intended policy for matching traffic.

Assess the effective saprouttab, identify overlapping rules, and report policy conflicts as configuration risks. Confirm the exact router release and approved lab test matrix; do not infer remote exploitability from a text match alone.
