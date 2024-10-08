# Firmware support

Kernel modules sometimes need to load firmware files from the filesystem.
KMM supports copying firmware files from the [kmod image](kmod_image.md)
to the node's filesystem.  
The contents of `.spec.moduleLoader.container.modprobe.firmwarePath` are copied
on the node into the path specified in the `kmm-operator-manager-config` configMap
at `worker.setFirmwareClassPath` before `modprobe` is called to insert the kernel module.
All files and empty directories are removed from that location before `modprobe -r` is called to unload the kernel
module, when the pod is terminated.

## Building a kmod image

In addition to building the kernel module itself, include the binary firmware in the builder image.

```dockerfile
FROM registry.redhat.io/ubi9/ubi-minimal as builder

# Build the kmod

RUN ["mkdir", "/firmware"]
RUN ["curl", "-o", "/firmware/firmware.bin", "https://artifacts.example.com/firmware.bin"]

FROM registry.redhat.io/ubi9/ubi-minimal

# Copy the kmod, install modprobe, run depmod

COPY --from=builder /firmware /firmware
```

## Tuning the `Module` resource

Set `.spec.moduleLoader.container.modprobe.firmwarePath` in the `Module` CR:

```yaml
apiVersion: kmm.sigs.x-k8s.io/v1beta1
kind: Module
metadata:
  name: my-kmod
spec:
  moduleLoader:
    container:
      modprobe:
        moduleName: my-kmod  # Required

        # Optional. Will copy /firmware/* on the node into the path specified
        # in the `kmm-operator-manager-config` at `worker.setFirmwareClassPath`
        # before `modprobe` is called to insert the kernel module..
        firmwarePath: /firmware
        
        # Add kernel mappings
  selector:
    node-role.kubernetes.io/worker: ""
```

## Setting the kernel's firmware search path

The Linux kernel accepts the `firmware_class.path` parameter as a
[search path for firmwares](https://www.kernel.org/doc/html/latest/driver-api/firmware/fw_search_path.html).
Since version 2.0.0, KMM workers can set that value on nodes by writing to sysfs, before attempting to load kmods.  
To enable that feature, set `worker.setFirmwareClassPath` in the
[operator configuration](configure.md#workersetfirmwareclasspath).  
The default value is `/var/lib/firmware`
