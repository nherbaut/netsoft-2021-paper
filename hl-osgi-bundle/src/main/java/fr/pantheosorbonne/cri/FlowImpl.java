package fr.pantheosorbonne.cri;

import java.io.StringReader;

import com.google.gson.Gson;

public class FlowImpl {

    public FlowImpl() {

    }

    private static Gson gson = new Gson();

    public String event;

    public int table = -1;
    public boolean icmp = false;
    public String reason = "";
    public boolean arp = false;
    public int in_port = -1;
    public String dl_src = "";
    public String dl_dst = "";
    public String arp_spa = "";
    public String arp_tpa = "";
    public int arp_op = -1;
    public int nw_tos = -1;
    public int icmp_type = -1;
    public int icmp_code = -1;
    public String actions = "";
    String device = "";
    double timestamp;

    public static FlowImpl deserialize(byte[] data) {
        return gson.fromJson(new StringReader(new String(data)), FlowImpl.class);

    }

    public static byte[] serialize(FlowImpl FlowImpl) {
        return gson.toJson(FlowImpl).getBytes();
    }

    public static FlowImpl createInstance() {
        return new FlowImpl();
    }

    /**
     * Factory method to create a FlowImpl object
     */
    public static Serializable createInstance(String deviceId, double timestamp, String event, int table, boolean icmp,
            String reason, boolean arp, int in_port, String dl_src, String dl_dst, String arp_spa, String arp_tpa,
            int arp_op, int nw_tos, int icmp_type, int icmp_code, String actions) {
        return (Serializable) new FlowImpl().setEvent(event).setTable(table).setIcmp(icmp).setReason(reason).setArp(arp)
                .setIn_port(in_port).setDl_src(dl_src).setDl_dst(dl_dst).setArp_spa(arp_spa).setArp_tpa(arp_tpa)
                .setArp_op(arp_op).setNw_tos(nw_tos).setIcmp_type(icmp_type).setDevice(deviceId)
                .setTimestamp(timestamp);
    }

    public String getEvent() {
        return event;
    }

    public int getTable() {
        return table;
    }

    public boolean isIcmp() {
        return icmp;
    }

    public String getReason() {
        return reason;
    }

    public boolean isArp() {
        return arp;
    }

    public int getIn_port() {
        return in_port;
    }

    public String getDl_src() {
        return dl_src;
    }

    public String getDl_dst() {
        return dl_dst;
    }

    public String getArp_spa() {
        return arp_spa;
    }

    public String getArp_tpa() {
        return arp_tpa;
    }

    public int getArp_op() {
        return arp_op;
    }

    public int getNw_tos() {
        return nw_tos;
    }

    public int getIcmp_type() {
        return icmp_type;
    }

    public int getIcmp_code() {
        return icmp_code;
    }

    public String getActions() {
        return actions;
    }

    public FlowImpl setEvent(String event) {
        this.event = event;
        return this;
    }

    public FlowImpl setTable(int table) {
        this.table = table;
        return this;
    }

    public FlowImpl setIcmp(boolean icmp) {
        this.icmp = icmp;
        return this;
    }

    public FlowImpl setReason(String reason) {
        this.reason = reason;
        return this;
    }

    public FlowImpl setArp(boolean arp) {
        this.arp = arp;
        return this;
    }

    public FlowImpl setIn_port(int in_port) {
        this.in_port = in_port;
        return this;
    }

    public FlowImpl setDl_src(String dl_src) {
        this.dl_src = dl_src;
        return this;
    }

    public FlowImpl setDl_dst(String dl_dst) {
        this.dl_dst = dl_dst;
        return this;
    }

    public FlowImpl setArp_spa(String arp_spa) {
        this.arp_spa = arp_spa;
        return this;
    }

    public FlowImpl setArp_tpa(String arp_tpa) {
        this.arp_tpa = arp_tpa;
        return this;
    }

    public FlowImpl setArp_op(int arp_op) {
        this.arp_op = arp_op;
        return this;
    }

    public FlowImpl setNw_tos(int nw_tos) {
        this.nw_tos = nw_tos;
        return this;
    }

    public FlowImpl setIcmp_type(int icmp_type) {
        this.icmp_type = icmp_type;
        return this;
    }

    public FlowImpl setIcmp_code(int icmp_code) {
        this.icmp_code = icmp_code;
        return this;
    }

    public FlowImpl setActions(String actions) {
        this.actions = actions;
        return this;
    }

    public String getDevice() {
        return device;
    }

    public double getTimestamp() {
        return timestamp;
    }

    public FlowImpl setDevice(String device) {
        this.device = device;
        return this;
    }

    public FlowImpl setTimestamp(double timestamp) {
        this.timestamp = timestamp;
        return this;
    }

}
