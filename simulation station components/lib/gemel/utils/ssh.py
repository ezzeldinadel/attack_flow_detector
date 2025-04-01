# def export_keys_to(vm_name):
#
#     with open("{HOME}/.ssh/id_rsa.pub".format(**environ)) as f:
#         pubkey = f.read()
#
#     gcloud = "{HOME}/.local/share/google-cloud-sdk/bin/gcloud".format(**environ)
#
#     bash_run("{gcloud} compute ssh root@{vm_name} -- "
#              "date"
#              .format(gcloud=gcloud, vm_name=vm_name, pubkey=pubkey))





