
%Ѱ����a������b�е�Ԫ��
function y=cellxor(a,b)
           y={};
           na=size(a,2);%a,b��Ϊ������
           nb=size(b,2);
           for i=1:na
               count=1;
               for j=1:nb
                   temp=(a{i}~=b{j});
                   judge=sum(sum(temp));
                   if judge==0 
                       count=0;
                       break;
                   end
               end
               if count==1
                   y=[y a(i)];
               end
           end
%            if size(y,2)~=1
%                y(1)=[];
%            end       
end
